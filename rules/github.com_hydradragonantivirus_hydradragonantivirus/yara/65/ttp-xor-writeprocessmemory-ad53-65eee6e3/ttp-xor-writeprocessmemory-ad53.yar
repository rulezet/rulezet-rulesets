rule TTP_XOR_WriteProcessMemory_ad53 {
  strings:
    $key_ad53 = { fa 21 [2] c8 03 [2] ce 36 [2] e0 36 [2] df 2a }

  condition:
    any of them
}