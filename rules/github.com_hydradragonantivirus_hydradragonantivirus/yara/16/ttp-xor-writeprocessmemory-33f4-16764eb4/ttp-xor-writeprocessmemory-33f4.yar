rule TTP_XOR_WriteProcessMemory_33f4 {
  strings:
    $key_33f4 = { 64 86 [2] 56 a4 [2] 50 91 [2] 7e 91 [2] 41 8d }

  condition:
    any of them
}