rule TTP_XOR_WriteProcessMemory_adf0 {
  strings:
    $key_adf0 = { fa 82 [2] c8 a0 [2] ce 95 [2] e0 95 [2] df 89 }

  condition:
    any of them
}