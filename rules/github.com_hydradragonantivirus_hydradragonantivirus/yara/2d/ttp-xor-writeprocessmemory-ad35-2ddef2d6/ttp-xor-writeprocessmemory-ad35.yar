rule TTP_XOR_WriteProcessMemory_ad35 {
  strings:
    $key_ad35 = { fa 47 [2] c8 65 [2] ce 50 [2] e0 50 [2] df 4c }

  condition:
    any of them
}