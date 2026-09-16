rule TTP_XOR_WriteProcessMemory_f981 {
  strings:
    $key_f981 = { ae f3 [2] 9c d1 [2] 9a e4 [2] b4 e4 [2] 8b f8 }

  condition:
    any of them
}