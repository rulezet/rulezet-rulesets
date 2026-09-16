rule TTP_XOR_WriteProcessMemory_4235 {
  strings:
    $key_4235 = { 15 47 [2] 27 65 [2] 21 50 [2] 0f 50 [2] 30 4c }

  condition:
    any of them
}