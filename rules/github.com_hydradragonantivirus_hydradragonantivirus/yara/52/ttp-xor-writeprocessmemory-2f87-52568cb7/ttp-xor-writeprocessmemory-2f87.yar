rule TTP_XOR_WriteProcessMemory_2f87 {
  strings:
    $key_2f87 = { 78 f5 [2] 4a d7 [2] 4c e2 [2] 62 e2 [2] 5d fe }

  condition:
    any of them
}