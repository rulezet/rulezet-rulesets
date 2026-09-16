rule TTP_XOR_WriteProcessMemory_3035 {
  strings:
    $key_3035 = { 67 47 [2] 55 65 [2] 53 50 [2] 7d 50 [2] 42 4c }

  condition:
    any of them
}