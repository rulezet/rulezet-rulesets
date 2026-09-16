rule TTP_XOR_WriteProcessMemory_e730 {
  strings:
    $key_e730 = { b0 42 [2] 82 60 [2] 84 55 [2] aa 55 [2] 95 49 }

  condition:
    any of them
}