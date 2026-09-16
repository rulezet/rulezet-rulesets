rule TTP_XOR_WriteProcessMemory_f9d6 {
  strings:
    $key_f9d6 = { ae a4 [2] 9c 86 [2] 9a b3 [2] b4 b3 [2] 8b af }

  condition:
    any of them
}