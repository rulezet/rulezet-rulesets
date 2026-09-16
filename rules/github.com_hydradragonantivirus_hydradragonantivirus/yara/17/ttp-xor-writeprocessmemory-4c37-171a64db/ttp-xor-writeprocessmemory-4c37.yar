rule TTP_XOR_WriteProcessMemory_4c37 {
  strings:
    $key_4c37 = { 1b 45 [2] 29 67 [2] 2f 52 [2] 01 52 [2] 3e 4e }

  condition:
    any of them
}