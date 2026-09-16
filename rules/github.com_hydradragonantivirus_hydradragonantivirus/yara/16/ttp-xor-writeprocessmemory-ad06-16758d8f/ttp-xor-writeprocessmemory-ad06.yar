rule TTP_XOR_WriteProcessMemory_ad06 {
  strings:
    $key_ad06 = { fa 74 [2] c8 56 [2] ce 63 [2] e0 63 [2] df 7f }

  condition:
    any of them
}