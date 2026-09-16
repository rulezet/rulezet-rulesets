rule TTP_XOR_WriteProcessMemory_3f37 {
  strings:
    $key_3f37 = { 68 45 [2] 5a 67 [2] 5c 52 [2] 72 52 [2] 4d 4e }

  condition:
    any of them
}