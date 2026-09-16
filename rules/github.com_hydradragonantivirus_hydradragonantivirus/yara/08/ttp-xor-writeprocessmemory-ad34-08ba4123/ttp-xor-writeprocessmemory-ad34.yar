rule TTP_XOR_WriteProcessMemory_ad34 {
  strings:
    $key_ad34 = { fa 46 [2] c8 64 [2] ce 51 [2] e0 51 [2] df 4d }

  condition:
    any of them
}