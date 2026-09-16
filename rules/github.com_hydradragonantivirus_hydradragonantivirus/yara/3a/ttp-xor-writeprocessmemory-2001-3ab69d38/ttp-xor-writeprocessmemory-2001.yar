rule TTP_XOR_WriteProcessMemory_2001 {
  strings:
    $key_2001 = { 77 73 [2] 45 51 [2] 43 64 [2] 6d 64 [2] 52 78 }

  condition:
    any of them
}