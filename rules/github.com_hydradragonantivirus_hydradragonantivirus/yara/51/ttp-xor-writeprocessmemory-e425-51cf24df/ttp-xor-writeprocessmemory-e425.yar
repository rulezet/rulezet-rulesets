rule TTP_XOR_WriteProcessMemory_e425 {
  strings:
    $key_e425 = { b3 57 [2] 81 75 [2] 87 40 [2] a9 40 [2] 96 5c }

  condition:
    any of them
}