rule TTP_XOR_WriteProcessMemory_136f {
  strings:
    $key_136f = { 44 1d [2] 76 3f [2] 70 0a [2] 5e 0a [2] 61 16 }

  condition:
    any of them
}