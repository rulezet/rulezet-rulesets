rule TTP_XOR_WriteProcessMemory_19c4 {
  strings:
    $key_19c4 = { 4e b6 [2] 7c 94 [2] 7a a1 [2] 54 a1 [2] 6b bd }

  condition:
    any of them
}