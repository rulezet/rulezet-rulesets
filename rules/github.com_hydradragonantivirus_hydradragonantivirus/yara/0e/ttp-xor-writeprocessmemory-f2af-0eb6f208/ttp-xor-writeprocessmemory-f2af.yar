rule TTP_XOR_WriteProcessMemory_f2af {
  strings:
    $key_f2af = { a5 dd [2] 97 ff [2] 91 ca [2] bf ca [2] 80 d6 }

  condition:
    any of them
}