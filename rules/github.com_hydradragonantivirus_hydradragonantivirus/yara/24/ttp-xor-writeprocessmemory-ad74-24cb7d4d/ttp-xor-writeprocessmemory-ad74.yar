rule TTP_XOR_WriteProcessMemory_ad74 {
  strings:
    $key_ad74 = { fa 06 [2] c8 24 [2] ce 11 [2] e0 11 [2] df 0d }

  condition:
    any of them
}