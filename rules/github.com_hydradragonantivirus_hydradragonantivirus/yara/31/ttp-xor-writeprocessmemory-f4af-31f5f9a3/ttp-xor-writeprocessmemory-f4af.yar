rule TTP_XOR_WriteProcessMemory_f4af {
  strings:
    $key_f4af = { a3 dd [2] 91 ff [2] 97 ca [2] b9 ca [2] 86 d6 }

  condition:
    any of them
}