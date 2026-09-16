rule TTP_XOR_WriteProcessMemory_ad62 {
  strings:
    $key_ad62 = { fa 10 [2] c8 32 [2] ce 07 [2] e0 07 [2] df 1b }

  condition:
    any of them
}