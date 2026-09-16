rule TTP_XOR_WriteProcessMemory_e3af {
  strings:
    $key_e3af = { b4 dd [2] 86 ff [2] 80 ca [2] ae ca [2] 91 d6 }

  condition:
    any of them
}