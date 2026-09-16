rule TTP_XOR_WriteProcessMemory_f817 {
  strings:
    $key_f817 = { af 65 [2] 9d 47 [2] 9b 72 [2] b5 72 [2] 8a 6e }

  condition:
    any of them
}