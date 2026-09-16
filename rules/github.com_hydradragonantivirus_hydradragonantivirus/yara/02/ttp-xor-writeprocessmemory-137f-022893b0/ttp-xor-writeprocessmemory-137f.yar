rule TTP_XOR_WriteProcessMemory_137f {
  strings:
    $key_137f = { 44 0d [2] 76 2f [2] 70 1a [2] 5e 1a [2] 61 06 }

  condition:
    any of them
}