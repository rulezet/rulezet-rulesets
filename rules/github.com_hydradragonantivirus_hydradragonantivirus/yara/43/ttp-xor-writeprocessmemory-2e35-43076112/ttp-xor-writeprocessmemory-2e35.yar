rule TTP_XOR_WriteProcessMemory_2e35 {
  strings:
    $key_2e35 = { 79 47 [2] 4b 65 [2] 4d 50 [2] 63 50 [2] 5c 4c }

  condition:
    any of them
}