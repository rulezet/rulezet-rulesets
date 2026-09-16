rule TTP_XOR_WriteProcessMemory_f8c5 {
  strings:
    $key_f8c5 = { af b7 [2] 9d 95 [2] 9b a0 [2] b5 a0 [2] 8a bc }

  condition:
    any of them
}