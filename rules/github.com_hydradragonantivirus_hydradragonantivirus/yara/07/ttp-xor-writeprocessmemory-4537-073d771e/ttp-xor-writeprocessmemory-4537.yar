rule TTP_XOR_WriteProcessMemory_4537 {
  strings:
    $key_4537 = { 12 45 [2] 20 67 [2] 26 52 [2] 08 52 [2] 37 4e }

  condition:
    any of them
}