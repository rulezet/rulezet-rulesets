rule TTP_XOR_WriteProcessMemory_7f37 {
  strings:
    $key_7f37 = { 28 45 [2] 1a 67 [2] 1c 52 [2] 32 52 [2] 0d 4e }

  condition:
    any of them
}