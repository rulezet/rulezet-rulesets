rule TTP_XOR_WriteProcessMemory_e637 {
  strings:
    $key_e637 = { b1 45 [2] 83 67 [2] 85 52 [2] ab 52 [2] 94 4e }

  condition:
    any of them
}