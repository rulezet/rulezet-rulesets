rule TTP_XOR_WriteProcessMemory_44f1 {
  strings:
    $key_44f1 = { 13 83 [2] 21 a1 [2] 27 94 [2] 09 94 [2] 36 88 }

  condition:
    any of them
}