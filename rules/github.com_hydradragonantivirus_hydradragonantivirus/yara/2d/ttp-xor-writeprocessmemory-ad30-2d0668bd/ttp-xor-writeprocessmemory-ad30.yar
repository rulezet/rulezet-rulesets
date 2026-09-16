rule TTP_XOR_WriteProcessMemory_ad30 {
  strings:
    $key_ad30 = { fa 42 [2] c8 60 [2] ce 55 [2] e0 55 [2] df 49 }

  condition:
    any of them
}