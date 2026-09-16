rule TTP_XOR_WriteProcessMemory_f585 {
  strings:
    $key_f585 = { a2 f7 [2] 90 d5 [2] 96 e0 [2] b8 e0 [2] 87 fc }

  condition:
    any of them
}