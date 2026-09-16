rule TTP_XOR_WriteProcessMemory_f8d2 {
  strings:
    $key_f8d2 = { af a0 [2] 9d 82 [2] 9b b7 [2] b5 b7 [2] 8a ab }

  condition:
    any of them
}