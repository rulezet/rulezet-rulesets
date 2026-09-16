rule TTP_XOR_WriteProcessMemory_0687 {
  strings:
    $key_0687 = { 51 f5 [2] 63 d7 [2] 65 e2 [2] 4b e2 [2] 74 fe }

  condition:
    any of them
}