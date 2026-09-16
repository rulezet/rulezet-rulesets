rule TTP_XOR_WriteProcessMemory_115f {
  strings:
    $key_115f = { 46 2d [2] 74 0f [2] 72 3a [2] 5c 3a [2] 63 26 }

  condition:
    any of them
}