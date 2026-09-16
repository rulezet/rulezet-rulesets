rule TTP_XOR_WriteProcessMemory_6687 {
  strings:
    $key_6687 = { 31 f5 [2] 03 d7 [2] 05 e2 [2] 2b e2 [2] 14 fe }

  condition:
    any of them
}