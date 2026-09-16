rule TTP_XOR_WriteProcessMemory_f9f5 {
  strings:
    $key_f9f5 = { ae 87 [2] 9c a5 [2] 9a 90 [2] b4 90 [2] 8b 8c }

  condition:
    any of them
}