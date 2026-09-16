rule TTP_XOR_WriteProcessMemory_2593 {
  strings:
    $key_2593 = { 72 e1 [2] 40 c3 [2] 46 f6 [2] 68 f6 [2] 57 ea }

  condition:
    any of them
}