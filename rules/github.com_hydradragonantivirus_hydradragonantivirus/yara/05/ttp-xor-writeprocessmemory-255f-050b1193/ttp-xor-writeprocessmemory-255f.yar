rule TTP_XOR_WriteProcessMemory_255f {
  strings:
    $key_255f = { 72 2d [2] 40 0f [2] 46 3a [2] 68 3a [2] 57 26 }

  condition:
    any of them
}