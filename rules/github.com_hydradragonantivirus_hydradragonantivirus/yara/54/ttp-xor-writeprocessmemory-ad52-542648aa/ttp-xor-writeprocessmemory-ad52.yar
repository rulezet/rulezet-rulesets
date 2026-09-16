rule TTP_XOR_WriteProcessMemory_ad52 {
  strings:
    $key_ad52 = { fa 20 [2] c8 02 [2] ce 37 [2] e0 37 [2] df 2b }

  condition:
    any of them
}