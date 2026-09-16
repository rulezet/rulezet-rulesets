rule TTP_XOR_WriteProcessMemory_e0ca {
  strings:
    $key_e0ca = { b7 b8 [2] 85 9a [2] 83 af [2] ad af [2] 92 b3 }

  condition:
    any of them
}