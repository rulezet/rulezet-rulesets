rule TTP_XOR_WriteProcessMemory_49af {
  strings:
    $key_49af = { 1e dd [2] 2c ff [2] 2a ca [2] 04 ca [2] 3b d6 }

  condition:
    any of them
}