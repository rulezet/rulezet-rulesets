rule TTP_XOR_WriteProcessMemory_4487 {
  strings:
    $key_4487 = { 13 f5 [2] 21 d7 [2] 27 e2 [2] 09 e2 [2] 36 fe }

  condition:
    any of them
}