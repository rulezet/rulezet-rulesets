rule TTP_XOR_WriteProcessMemory_cbf3 {
  strings:
    $key_cbf3 = { 9c 81 [2] ae a3 [2] a8 96 [2] 86 96 [2] b9 8a }

  condition:
    any of them
}