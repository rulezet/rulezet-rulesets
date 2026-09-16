rule TTP_XOR_WriteProcessMemory_ad00 {
  strings:
    $key_ad00 = { fa 72 [2] c8 50 [2] ce 65 [2] e0 65 [2] df 79 }

  condition:
    any of them
}