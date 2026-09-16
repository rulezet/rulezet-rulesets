rule TTP_XOR_WriteProcessMemory_3a8d {
  strings:
    $key_3a8d = { 6d ff [2] 5f dd [2] 59 e8 [2] 77 e8 [2] 48 f4 }

  condition:
    any of them
}