rule TTP_XOR_WriteProcessMemory_cbf0 {
  strings:
    $key_cbf0 = { 9c 82 [2] ae a0 [2] a8 95 [2] 86 95 [2] b9 89 }

  condition:
    any of them
}