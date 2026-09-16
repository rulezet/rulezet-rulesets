rule TTP_XOR_WriteProcessMemory_e779 {
  strings:
    $key_e779 = { b0 0b [2] 82 29 [2] 84 1c [2] aa 1c [2] 95 00 }

  condition:
    any of them
}