rule TTP_XOR_WriteProcessMemory_f843 {
  strings:
    $key_f843 = { af 31 [2] 9d 13 [2] 9b 26 [2] b5 26 [2] 8a 3a }

  condition:
    any of them
}