rule TTP_XOR_WriteProcessMemory_1937 {
  strings:
    $key_1937 = { 4e 45 [2] 7c 67 [2] 7a 52 [2] 54 52 [2] 6b 4e }

  condition:
    any of them
}