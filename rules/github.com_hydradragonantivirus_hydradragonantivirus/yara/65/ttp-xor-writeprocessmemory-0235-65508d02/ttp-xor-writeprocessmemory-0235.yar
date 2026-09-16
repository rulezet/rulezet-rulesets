rule TTP_XOR_WriteProcessMemory_0235 {
  strings:
    $key_0235 = { 55 47 [2] 67 65 [2] 61 50 [2] 4f 50 [2] 70 4c }

  condition:
    any of them
}