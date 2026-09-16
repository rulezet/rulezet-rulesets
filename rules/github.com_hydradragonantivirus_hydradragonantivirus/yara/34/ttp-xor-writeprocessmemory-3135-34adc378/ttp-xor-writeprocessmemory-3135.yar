rule TTP_XOR_WriteProcessMemory_3135 {
  strings:
    $key_3135 = { 66 47 [2] 54 65 [2] 52 50 [2] 7c 50 [2] 43 4c }

  condition:
    any of them
}