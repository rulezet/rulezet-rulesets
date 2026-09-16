rule TTP_XOR_WriteProcessMemory_ad18 {
  strings:
    $key_ad18 = { fa 6a [2] c8 48 [2] ce 7d [2] e0 7d [2] df 61 }

  condition:
    any of them
}