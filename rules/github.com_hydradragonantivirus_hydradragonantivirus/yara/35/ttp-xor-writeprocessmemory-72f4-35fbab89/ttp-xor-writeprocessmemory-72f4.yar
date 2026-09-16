rule TTP_XOR_WriteProcessMemory_72f4 {
  strings:
    $key_72f4 = { 25 86 [2] 17 a4 [2] 11 91 [2] 3f 91 [2] 00 8d }

  condition:
    any of them
}