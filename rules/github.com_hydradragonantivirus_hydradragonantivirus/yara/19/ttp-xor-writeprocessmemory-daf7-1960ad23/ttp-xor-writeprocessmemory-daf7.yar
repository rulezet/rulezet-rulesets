rule TTP_XOR_WriteProcessMemory_daf7 {
  strings:
    $key_daf7 = { 8d 85 [2] bf a7 [2] b9 92 [2] 97 92 [2] a8 8e }

  condition:
    any of them
}