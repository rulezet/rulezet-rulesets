rule TTP_XOR_WriteProcessMemory_2a8d {
  strings:
    $key_2a8d = { 7d ff [2] 4f dd [2] 49 e8 [2] 67 e8 [2] 58 f4 }

  condition:
    any of them
}