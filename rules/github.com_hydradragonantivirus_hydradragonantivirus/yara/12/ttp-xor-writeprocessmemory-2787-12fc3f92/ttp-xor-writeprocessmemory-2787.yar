rule TTP_XOR_WriteProcessMemory_2787 {
  strings:
    $key_2787 = { 70 f5 [2] 42 d7 [2] 44 e2 [2] 6a e2 [2] 55 fe }

  condition:
    any of them
}