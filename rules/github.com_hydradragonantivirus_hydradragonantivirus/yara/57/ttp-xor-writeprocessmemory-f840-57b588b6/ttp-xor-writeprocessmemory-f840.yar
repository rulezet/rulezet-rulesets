rule TTP_XOR_WriteProcessMemory_f840 {
  strings:
    $key_f840 = { af 32 [2] 9d 10 [2] 9b 25 [2] b5 25 [2] 8a 39 }

  condition:
    any of them
}