rule TTP_XOR_WriteProcessMemory_ade7 {
  strings:
    $key_ade7 = { fa 95 [2] c8 b7 [2] ce 82 [2] e0 82 [2] df 9e }

  condition:
    any of them
}