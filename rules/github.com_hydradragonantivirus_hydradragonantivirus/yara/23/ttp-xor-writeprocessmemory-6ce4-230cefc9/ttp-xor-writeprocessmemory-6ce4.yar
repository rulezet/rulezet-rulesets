rule TTP_XOR_WriteProcessMemory_6ce4 {
  strings:
    $key_6ce4 = { 3b 96 [2] 09 b4 [2] 0f 81 [2] 21 81 [2] 1e 9d }

  condition:
    any of them
}