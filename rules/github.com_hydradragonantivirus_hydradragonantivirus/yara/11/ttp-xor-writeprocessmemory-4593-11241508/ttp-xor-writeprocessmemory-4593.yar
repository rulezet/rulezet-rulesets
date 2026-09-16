rule TTP_XOR_WriteProcessMemory_4593 {
  strings:
    $key_4593 = { 12 e1 [2] 20 c3 [2] 26 f6 [2] 08 f6 [2] 37 ea }

  condition:
    any of them
}