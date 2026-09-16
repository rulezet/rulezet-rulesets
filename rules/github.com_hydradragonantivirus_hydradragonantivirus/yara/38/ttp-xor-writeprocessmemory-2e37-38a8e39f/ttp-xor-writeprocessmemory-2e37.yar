rule TTP_XOR_WriteProcessMemory_2e37 {
  strings:
    $key_2e37 = { 79 45 [2] 4b 67 [2] 4d 52 [2] 63 52 [2] 5c 4e }

  condition:
    any of them
}