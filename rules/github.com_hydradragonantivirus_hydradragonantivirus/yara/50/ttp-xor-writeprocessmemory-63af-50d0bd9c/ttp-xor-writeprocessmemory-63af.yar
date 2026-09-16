rule TTP_XOR_WriteProcessMemory_63af {
  strings:
    $key_63af = { 34 dd [2] 06 ff [2] 00 ca [2] 2e ca [2] 11 d6 }

  condition:
    any of them
}