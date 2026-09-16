rule TTP_XOR_WriteProcessMemory_4ad9 {
  strings:
    $key_4ad9 = { 1d ab [2] 2f 89 [2] 29 bc [2] 07 bc [2] 38 a0 }

  condition:
    any of them
}