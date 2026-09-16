rule TTP_XOR_WriteProcessMemory_3a93 {
  strings:
    $key_3a93 = { 6d e1 [2] 5f c3 [2] 59 f6 [2] 77 f6 [2] 48 ea }

  condition:
    any of them
}