rule TTP_XOR_WriteProcessMemory_f9e1 {
  strings:
    $key_f9e1 = { ae 93 [2] 9c b1 [2] 9a 84 [2] b4 84 [2] 8b 98 }

  condition:
    any of them
}