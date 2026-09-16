rule TTP_XOR_WriteProcessMemory_f6af {
  strings:
    $key_f6af = { a1 dd [2] 93 ff [2] 95 ca [2] bb ca [2] 84 d6 }

  condition:
    any of them
}