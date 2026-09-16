rule TTP_XOR_WriteProcessMemory_e715 {
  strings:
    $key_e715 = { b0 67 [2] 82 45 [2] 84 70 [2] aa 70 [2] 95 6c }

  condition:
    any of them
}