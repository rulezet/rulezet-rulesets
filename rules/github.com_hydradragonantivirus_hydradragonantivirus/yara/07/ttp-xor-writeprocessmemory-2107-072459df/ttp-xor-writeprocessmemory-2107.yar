rule TTP_XOR_WriteProcessMemory_2107 {
  strings:
    $key_2107 = { 76 75 [2] 44 57 [2] 42 62 [2] 6c 62 [2] 53 7e }

  condition:
    any of them
}