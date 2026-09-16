rule TTP_XOR_WriteProcessMemory_ad16 {
  strings:
    $key_ad16 = { fa 64 [2] c8 46 [2] ce 73 [2] e0 73 [2] df 6f }

  condition:
    any of them
}