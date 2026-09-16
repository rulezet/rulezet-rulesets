rule TTP_XOR_WriteProcessMemory_f9d4 {
  strings:
    $key_f9d4 = { ae a6 [2] 9c 84 [2] 9a b1 [2] b4 b1 [2] 8b ad }

  condition:
    any of them
}