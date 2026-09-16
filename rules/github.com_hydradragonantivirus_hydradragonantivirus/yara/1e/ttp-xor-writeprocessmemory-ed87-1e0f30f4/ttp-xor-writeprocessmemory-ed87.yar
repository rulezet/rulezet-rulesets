rule TTP_XOR_WriteProcessMemory_ed87 {
  strings:
    $key_ed87 = { ba f5 [2] 88 d7 [2] 8e e2 [2] a0 e2 [2] 9f fe }

  condition:
    any of them
}