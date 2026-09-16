rule TTP_XOR_WriteProcessMemory_73af {
  strings:
    $key_73af = { 24 dd [2] 16 ff [2] 10 ca [2] 3e ca [2] 01 d6 }

  condition:
    any of them
}