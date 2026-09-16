rule TTP_XOR_WriteProcessMemory_1337 {
  strings:
    $key_1337 = { 44 45 [2] 76 67 [2] 70 52 [2] 5e 52 [2] 61 4e }

  condition:
    any of them
}