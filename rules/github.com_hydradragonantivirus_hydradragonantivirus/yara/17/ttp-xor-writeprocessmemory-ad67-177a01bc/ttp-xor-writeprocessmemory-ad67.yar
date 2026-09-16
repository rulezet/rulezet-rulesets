rule TTP_XOR_WriteProcessMemory_ad67 {
  strings:
    $key_ad67 = { fa 15 [2] c8 37 [2] ce 02 [2] e0 02 [2] df 1e }

  condition:
    any of them
}