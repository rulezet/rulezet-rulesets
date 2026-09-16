rule TTP_XOR_WriteProcessMemory_4047 {
  strings:
    $key_4047 = { 17 35 [2] 25 17 [2] 23 22 [2] 0d 22 [2] 32 3e }

  condition:
    any of them
}