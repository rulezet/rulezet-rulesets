rule TTP_XOR_WriteProcessMemory_ad10 {
  strings:
    $key_ad10 = { fa 62 [2] c8 40 [2] ce 75 [2] e0 75 [2] df 69 }

  condition:
    any of them
}