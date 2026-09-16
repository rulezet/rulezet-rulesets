rule TTP_XOR_WriteProcessMemory_e709 {
  strings:
    $key_e709 = { b0 7b [2] 82 59 [2] 84 6c [2] aa 6c [2] 95 70 }

  condition:
    any of them
}