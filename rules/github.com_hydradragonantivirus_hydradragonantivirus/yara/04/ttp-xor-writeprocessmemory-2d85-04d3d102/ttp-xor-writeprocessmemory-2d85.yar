rule TTP_XOR_WriteProcessMemory_2d85 {
  strings:
    $key_2d85 = { 7a f7 [2] 48 d5 [2] 4e e0 [2] 60 e0 [2] 5f fc }

  condition:
    any of them
}