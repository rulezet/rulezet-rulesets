rule TTP_XOR_WriteProcessMemory_adf1 {
  strings:
    $key_adf1 = { fa 83 [2] c8 a1 [2] ce 94 [2] e0 94 [2] df 88 }

  condition:
    any of them
}