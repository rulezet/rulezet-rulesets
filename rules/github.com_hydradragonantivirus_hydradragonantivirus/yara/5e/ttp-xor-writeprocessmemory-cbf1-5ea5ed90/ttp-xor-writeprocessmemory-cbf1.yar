rule TTP_XOR_WriteProcessMemory_cbf1 {
  strings:
    $key_cbf1 = { 9c 83 [2] ae a1 [2] a8 94 [2] 86 94 [2] b9 88 }

  condition:
    any of them
}