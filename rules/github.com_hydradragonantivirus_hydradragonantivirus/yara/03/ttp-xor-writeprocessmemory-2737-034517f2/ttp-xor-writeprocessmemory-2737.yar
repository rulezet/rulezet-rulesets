rule TTP_XOR_WriteProcessMemory_2737 {
  strings:
    $key_2737 = { 70 45 [2] 42 67 [2] 44 52 [2] 6a 52 [2] 55 4e }

  condition:
    any of them
}