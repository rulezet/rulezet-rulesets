rule TTP_XOR_WriteProcessMemory_2137 {
  strings:
    $key_2137 = { 76 45 [2] 44 67 [2] 42 52 [2] 6c 52 [2] 53 4e }

  condition:
    any of them
}