rule TTP_XOR_WriteProcessMemory_4035 {
  strings:
    $key_4035 = { 17 47 [2] 25 65 [2] 23 50 [2] 0d 50 [2] 32 4c }

  condition:
    any of them
}