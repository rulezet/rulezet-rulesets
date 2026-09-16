rule TTP_XOR_WriteProcessMemory_f8c2 {
  strings:
    $key_f8c2 = { af b0 [2] 9d 92 [2] 9b a7 [2] b5 a7 [2] 8a bb }

  condition:
    any of them
}