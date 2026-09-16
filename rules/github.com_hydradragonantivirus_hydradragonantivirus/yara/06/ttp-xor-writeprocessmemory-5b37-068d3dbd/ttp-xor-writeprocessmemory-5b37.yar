rule TTP_XOR_WriteProcessMemory_5b37 {
  strings:
    $key_5b37 = { 0c 45 [2] 3e 67 [2] 38 52 [2] 16 52 [2] 29 4e }

  condition:
    any of them
}