rule TTP_XOR_WriteProcessMemory_3722 {
  strings:
    $key_3722 = { 60 50 [2] 52 72 [2] 54 47 [2] 7a 47 [2] 45 5b }

  condition:
    any of them
}