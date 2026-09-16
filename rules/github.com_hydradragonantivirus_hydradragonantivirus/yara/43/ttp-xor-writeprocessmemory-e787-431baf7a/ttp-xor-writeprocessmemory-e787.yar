rule TTP_XOR_WriteProcessMemory_e787 {
  strings:
    $key_e787 = { b0 f5 [2] 82 d7 [2] 84 e2 [2] aa e2 [2] 95 fe }

  condition:
    any of them
}