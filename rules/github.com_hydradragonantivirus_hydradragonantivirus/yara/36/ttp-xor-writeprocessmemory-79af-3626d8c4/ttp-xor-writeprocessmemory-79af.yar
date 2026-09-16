rule TTP_XOR_WriteProcessMemory_79af {
  strings:
    $key_79af = { 2e dd [2] 1c ff [2] 1a ca [2] 34 ca [2] 0b d6 }

  condition:
    any of them
}