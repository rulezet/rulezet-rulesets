rule TTP_XOR_WriteProcessMemory_5325 {
  strings:
    $key_5325 = { 04 57 [2] 36 75 [2] 30 40 [2] 1e 40 [2] 21 5c }

  condition:
    any of them
}