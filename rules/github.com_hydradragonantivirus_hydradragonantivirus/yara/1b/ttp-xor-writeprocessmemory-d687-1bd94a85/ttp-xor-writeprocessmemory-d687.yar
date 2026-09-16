rule TTP_XOR_WriteProcessMemory_d687 {
  strings:
    $key_d687 = { 81 f5 [2] b3 d7 [2] b5 e2 [2] 9b e2 [2] a4 fe }

  condition:
    any of them
}