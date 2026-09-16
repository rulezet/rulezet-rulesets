rule TTP_XOR_WriteProcessMemory_57af {
  strings:
    $key_57af = { 00 dd [2] 32 ff [2] 34 ca [2] 1a ca [2] 25 d6 }

  condition:
    any of them
}