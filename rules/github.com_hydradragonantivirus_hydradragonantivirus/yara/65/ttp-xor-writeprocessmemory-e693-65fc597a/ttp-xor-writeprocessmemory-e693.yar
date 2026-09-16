rule TTP_XOR_WriteProcessMemory_e693 {
  strings:
    $key_e693 = { b1 e1 [2] 83 c3 [2] 85 f6 [2] ab f6 [2] 94 ea }

  condition:
    any of them
}