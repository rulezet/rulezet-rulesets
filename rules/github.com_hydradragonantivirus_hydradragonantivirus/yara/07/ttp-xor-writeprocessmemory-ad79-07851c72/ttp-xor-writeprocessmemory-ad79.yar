rule TTP_XOR_WriteProcessMemory_ad79 {
  strings:
    $key_ad79 = { fa 0b [2] c8 29 [2] ce 1c [2] e0 1c [2] df 00 }

  condition:
    any of them
}