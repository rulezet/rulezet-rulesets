rule TTP_XOR_WriteProcessMemory_ad27 {
  strings:
    $key_ad27 = { fa 55 [2] c8 77 [2] ce 42 [2] e0 42 [2] df 5e }

  condition:
    any of them
}