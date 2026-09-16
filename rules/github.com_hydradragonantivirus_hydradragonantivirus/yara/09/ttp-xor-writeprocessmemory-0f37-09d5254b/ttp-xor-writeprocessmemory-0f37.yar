rule TTP_XOR_WriteProcessMemory_0f37 {
  strings:
    $key_0f37 = { 58 45 [2] 6a 67 [2] 6c 52 [2] 42 52 [2] 7d 4e }

  condition:
    any of them
}