rule TTP_XOR_WriteProcessMemory_ad61 {
  strings:
    $key_ad61 = { fa 13 [2] c8 31 [2] ce 04 [2] e0 04 [2] df 18 }

  condition:
    any of them
}