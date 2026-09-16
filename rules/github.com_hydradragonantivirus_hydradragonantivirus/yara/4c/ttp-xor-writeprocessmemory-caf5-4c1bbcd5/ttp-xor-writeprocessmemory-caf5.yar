rule TTP_XOR_WriteProcessMemory_caf5 {
  strings:
    $key_caf5 = { 9d 87 [2] af a5 [2] a9 90 [2] 87 90 [2] b8 8c }

  condition:
    any of them
}