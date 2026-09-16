rule TTP_XOR_WriteProcessMemory_7593 {
  strings:
    $key_7593 = { 22 e1 [2] 10 c3 [2] 16 f6 [2] 38 f6 [2] 07 ea }

  condition:
    any of them
}