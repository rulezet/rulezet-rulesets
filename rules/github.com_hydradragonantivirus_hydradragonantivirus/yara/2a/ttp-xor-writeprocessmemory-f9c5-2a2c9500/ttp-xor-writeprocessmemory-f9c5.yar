rule TTP_XOR_WriteProcessMemory_f9c5 {
  strings:
    $key_f9c5 = { ae b7 [2] 9c 95 [2] 9a a0 [2] b4 a0 [2] 8b bc }

  condition:
    any of them
}