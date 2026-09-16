rule TTP_XOR_WriteProcessMemory_c579 {
  strings:
    $key_c579 = { 92 0b [2] a0 29 [2] a6 1c [2] 88 1c [2] b7 00 }

  condition:
    any of them
}