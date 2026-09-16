rule TTP_XOR_WriteProcessMemory_f9d5 {
  strings:
    $key_f9d5 = { ae a7 [2] 9c 85 [2] 9a b0 [2] b4 b0 [2] 8b ac }

  condition:
    any of them
}