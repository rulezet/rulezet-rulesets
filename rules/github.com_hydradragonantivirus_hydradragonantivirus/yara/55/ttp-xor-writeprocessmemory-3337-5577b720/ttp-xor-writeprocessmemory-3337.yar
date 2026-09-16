rule TTP_XOR_WriteProcessMemory_3337 {
  strings:
    $key_3337 = { 64 45 [2] 56 67 [2] 50 52 [2] 7e 52 [2] 41 4e }

  condition:
    any of them
}