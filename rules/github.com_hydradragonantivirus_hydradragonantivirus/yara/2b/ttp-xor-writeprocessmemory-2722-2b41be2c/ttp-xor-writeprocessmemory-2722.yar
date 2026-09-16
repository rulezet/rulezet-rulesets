rule TTP_XOR_WriteProcessMemory_2722 {
  strings:
    $key_2722 = { 70 50 [2] 42 72 [2] 44 47 [2] 6a 47 [2] 55 5b }

  condition:
    any of them
}