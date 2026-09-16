rule TTP_XOR_WriteProcessMemory_265f {
  strings:
    $key_265f = { 71 2d [2] 43 0f [2] 45 3a [2] 6b 3a [2] 54 26 }

  condition:
    any of them
}