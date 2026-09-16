rule TTP_XOR_WriteProcessMemory_3493 {
  strings:
    $key_3493 = { 63 e1 [2] 51 c3 [2] 57 f6 [2] 79 f6 [2] 46 ea }

  condition:
    any of them
}