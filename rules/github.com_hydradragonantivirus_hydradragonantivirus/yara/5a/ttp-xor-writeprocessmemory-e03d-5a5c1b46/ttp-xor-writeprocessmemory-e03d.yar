rule TTP_XOR_WriteProcessMemory_e03d {
  strings:
    $key_e03d = { b7 4f [2] 85 6d [2] 83 58 [2] ad 58 [2] 92 44 }

  condition:
    any of them
}