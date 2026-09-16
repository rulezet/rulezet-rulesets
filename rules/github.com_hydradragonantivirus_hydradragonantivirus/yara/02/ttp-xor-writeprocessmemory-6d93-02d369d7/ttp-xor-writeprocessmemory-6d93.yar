rule TTP_XOR_WriteProcessMemory_6d93 {
  strings:
    $key_6d93 = { 3a e1 [2] 08 c3 [2] 0e f6 [2] 20 f6 [2] 1f ea }

  condition:
    any of them
}