rule TTP_XOR_WriteProcessMemory_7f7f {
  strings:
    $key_7f7f = { 28 0d [2] 1a 2f [2] 1c 1a [2] 32 1a [2] 0d 06 }

  condition:
    any of them
}