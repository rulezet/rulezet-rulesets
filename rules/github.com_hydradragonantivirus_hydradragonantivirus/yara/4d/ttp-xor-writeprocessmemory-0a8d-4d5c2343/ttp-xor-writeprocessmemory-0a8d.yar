rule TTP_XOR_WriteProcessMemory_0a8d {
  strings:
    $key_0a8d = { 5d ff [2] 6f dd [2] 69 e8 [2] 47 e8 [2] 78 f4 }

  condition:
    any of them
}