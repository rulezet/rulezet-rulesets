rule TTP_XOR_WriteProcessMemory_eff7 {
  strings:
    $key_eff7 = { b8 85 [2] 8a a7 [2] 8c 92 [2] a2 92 [2] 9d 8e }

  condition:
    any of them
}