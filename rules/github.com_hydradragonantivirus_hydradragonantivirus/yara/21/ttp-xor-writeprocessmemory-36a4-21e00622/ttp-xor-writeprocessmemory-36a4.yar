rule TTP_XOR_WriteProcessMemory_36a4 {
  strings:
    $key_36a4 = { 61 d6 [2] 53 f4 [2] 55 c1 [2] 7b c1 [2] 44 dd }

  condition:
    any of them
}