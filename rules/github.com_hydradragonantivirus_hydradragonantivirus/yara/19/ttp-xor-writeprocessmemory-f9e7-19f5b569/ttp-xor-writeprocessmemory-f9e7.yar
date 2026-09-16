rule TTP_XOR_WriteProcessMemory_f9e7 {
  strings:
    $key_f9e7 = { ae 95 [2] 9c b7 [2] 9a 82 [2] b4 82 [2] 8b 9e }

  condition:
    any of them
}