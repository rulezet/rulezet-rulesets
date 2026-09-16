rule TTP_XOR_WriteProcessMemory_caf7 {
  strings:
    $key_caf7 = { 9d 85 [2] af a7 [2] a9 92 [2] 87 92 [2] b8 8e }

  condition:
    any of them
}