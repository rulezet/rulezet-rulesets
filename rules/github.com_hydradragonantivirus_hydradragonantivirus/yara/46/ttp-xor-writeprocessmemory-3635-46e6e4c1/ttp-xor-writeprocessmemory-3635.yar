rule TTP_XOR_WriteProcessMemory_3635 {
  strings:
    $key_3635 = { 61 47 [2] 53 65 [2] 55 50 [2] 7b 50 [2] 44 4c }

  condition:
    any of them
}