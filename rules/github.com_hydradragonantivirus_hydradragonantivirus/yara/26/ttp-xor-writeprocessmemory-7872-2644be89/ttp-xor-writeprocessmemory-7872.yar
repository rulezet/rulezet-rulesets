rule TTP_XOR_WriteProcessMemory_7872 {
  strings:
    $key_7872 = { 2f 00 [2] 1d 22 [2] 1b 17 [2] 35 17 [2] 0a 0b }

  condition:
    any of them
}