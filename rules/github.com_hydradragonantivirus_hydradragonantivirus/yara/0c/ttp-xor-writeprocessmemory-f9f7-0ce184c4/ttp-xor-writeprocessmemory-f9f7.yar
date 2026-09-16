rule TTP_XOR_WriteProcessMemory_f9f7 {
  strings:
    $key_f9f7 = { ae 85 [2] 9c a7 [2] 9a 92 [2] b4 92 [2] 8b 8e }

  condition:
    any of them
}