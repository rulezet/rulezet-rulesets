rule TTP_XOR_WriteProcessMemory_f920 {
  strings:
    $key_f920 = { ae 52 [2] 9c 70 [2] 9a 45 [2] b4 45 [2] 8b 59 }

  condition:
    any of them
}