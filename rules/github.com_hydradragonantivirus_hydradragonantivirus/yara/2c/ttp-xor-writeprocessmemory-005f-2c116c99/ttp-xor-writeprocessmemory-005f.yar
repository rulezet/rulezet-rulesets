rule TTP_XOR_WriteProcessMemory_005f {
  strings:
    $key_005f = { 57 2d [2] 65 0f [2] 63 3a [2] 4d 3a [2] 72 26 }

  condition:
    any of them
}