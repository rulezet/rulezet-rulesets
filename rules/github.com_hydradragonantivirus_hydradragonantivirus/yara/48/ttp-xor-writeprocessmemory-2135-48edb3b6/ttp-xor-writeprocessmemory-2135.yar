rule TTP_XOR_WriteProcessMemory_2135 {
  strings:
    $key_2135 = { 76 47 [2] 44 65 [2] 42 50 [2] 6c 50 [2] 53 4c }

  condition:
    any of them
}