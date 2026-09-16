rule TTP_XOR_WriteProcessMemory_ad43 {
  strings:
    $key_ad43 = { fa 31 [2] c8 13 [2] ce 26 [2] e0 26 [2] df 3a }

  condition:
    any of them
}