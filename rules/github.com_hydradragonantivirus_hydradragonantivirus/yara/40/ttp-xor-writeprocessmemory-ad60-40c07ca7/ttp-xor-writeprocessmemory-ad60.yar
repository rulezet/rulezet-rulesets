rule TTP_XOR_WriteProcessMemory_ad60 {
  strings:
    $key_ad60 = { fa 12 [2] c8 30 [2] ce 05 [2] e0 05 [2] df 19 }

  condition:
    any of them
}