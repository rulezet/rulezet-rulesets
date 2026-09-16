rule TTP_XOR_WriteProcessMemory_f9e2 {
  strings:
    $key_f9e2 = { ae 90 [2] 9c b2 [2] 9a 87 [2] b4 87 [2] 8b 9b }

  condition:
    any of them
}