rule TTP_XOR_WriteProcessMemory_ad55 {
  strings:
    $key_ad55 = { fa 27 [2] c8 05 [2] ce 30 [2] e0 30 [2] df 2c }

  condition:
    any of them
}