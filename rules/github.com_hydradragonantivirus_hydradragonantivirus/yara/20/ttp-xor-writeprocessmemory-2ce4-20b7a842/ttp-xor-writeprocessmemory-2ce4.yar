rule TTP_XOR_WriteProcessMemory_2ce4 {
  strings:
    $key_2ce4 = { 7b 96 [2] 49 b4 [2] 4f 81 [2] 61 81 [2] 5e 9d }

  condition:
    any of them
}