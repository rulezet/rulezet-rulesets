rule TTP_XOR_WriteProcessMemory_ad70 {
  strings:
    $key_ad70 = { fa 02 [2] c8 20 [2] ce 15 [2] e0 15 [2] df 09 }

  condition:
    any of them
}