rule TTP_XOR_WriteProcessMemory_e0f8 {
  strings:
    $key_e0f8 = { b7 8a [2] 85 a8 [2] 83 9d [2] ad 9d [2] 92 81 }

  condition:
    any of them
}