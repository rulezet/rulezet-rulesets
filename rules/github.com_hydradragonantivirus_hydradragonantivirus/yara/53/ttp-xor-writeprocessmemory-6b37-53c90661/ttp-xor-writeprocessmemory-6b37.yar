rule TTP_XOR_WriteProcessMemory_6b37 {
  strings:
    $key_6b37 = { 3c 45 [2] 0e 67 [2] 08 52 [2] 26 52 [2] 19 4e }

  condition:
    any of them
}