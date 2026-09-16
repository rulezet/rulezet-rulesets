rule TTP_XOR_WriteProcessMemory_f9e6 {
  strings:
    $key_f9e6 = { ae 94 [2] 9c b6 [2] 9a 83 [2] b4 83 [2] 8b 9f }

  condition:
    any of them
}