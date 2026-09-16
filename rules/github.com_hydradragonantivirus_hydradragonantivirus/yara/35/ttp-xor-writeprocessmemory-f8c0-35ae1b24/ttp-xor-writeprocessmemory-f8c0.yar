rule TTP_XOR_WriteProcessMemory_f8c0 {
  strings:
    $key_f8c0 = { af b2 [2] 9d 90 [2] 9b a5 [2] b5 a5 [2] 8a b9 }

  condition:
    any of them
}