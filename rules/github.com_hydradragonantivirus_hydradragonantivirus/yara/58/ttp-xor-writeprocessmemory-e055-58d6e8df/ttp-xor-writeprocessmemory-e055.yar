rule TTP_XOR_WriteProcessMemory_e055 {
  strings:
    $key_e055 = { b7 27 [2] 85 05 [2] 83 30 [2] ad 30 [2] 92 2c }

  condition:
    any of them
}