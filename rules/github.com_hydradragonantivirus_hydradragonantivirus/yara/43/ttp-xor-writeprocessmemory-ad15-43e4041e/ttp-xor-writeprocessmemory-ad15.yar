rule TTP_XOR_WriteProcessMemory_ad15 {
  strings:
    $key_ad15 = { fa 67 [2] c8 45 [2] ce 70 [2] e0 70 [2] df 6c }

  condition:
    any of them
}