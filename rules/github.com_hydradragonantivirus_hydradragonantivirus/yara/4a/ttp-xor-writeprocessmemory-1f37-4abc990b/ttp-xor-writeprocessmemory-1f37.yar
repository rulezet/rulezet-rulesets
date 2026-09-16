rule TTP_XOR_WriteProcessMemory_1f37 {
  strings:
    $key_1f37 = { 48 45 [2] 7a 67 [2] 7c 52 [2] 52 52 [2] 6d 4e }

  condition:
    any of them
}