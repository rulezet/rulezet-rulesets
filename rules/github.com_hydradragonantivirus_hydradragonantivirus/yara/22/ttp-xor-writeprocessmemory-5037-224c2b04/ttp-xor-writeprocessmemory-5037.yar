rule TTP_XOR_WriteProcessMemory_5037 {
  strings:
    $key_5037 = { 07 45 [2] 35 67 [2] 33 52 [2] 1d 52 [2] 22 4e }

  condition:
    any of them
}