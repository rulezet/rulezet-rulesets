rule TTP_XOR_WriteProcessMemory_6dd2 {
  strings:
    $key_6dd2 = { 3a a0 [2] 08 82 [2] 0e b7 [2] 20 b7 [2] 1f ab }

  condition:
    any of them
}