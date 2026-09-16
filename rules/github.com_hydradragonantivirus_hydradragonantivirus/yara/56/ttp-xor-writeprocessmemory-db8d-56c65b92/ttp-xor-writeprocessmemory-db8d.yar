rule TTP_XOR_WriteProcessMemory_db8d {
  strings:
    $key_db8d = { 8c ff [2] be dd [2] b8 e8 [2] 96 e8 [2] a9 f4 }

  condition:
    any of them
}