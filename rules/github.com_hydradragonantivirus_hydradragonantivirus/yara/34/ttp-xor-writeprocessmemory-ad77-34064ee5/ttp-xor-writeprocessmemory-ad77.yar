rule TTP_XOR_WriteProcessMemory_ad77 {
  strings:
    $key_ad77 = { fa 05 [2] c8 27 [2] ce 12 [2] e0 12 [2] df 0e }

  condition:
    any of them
}