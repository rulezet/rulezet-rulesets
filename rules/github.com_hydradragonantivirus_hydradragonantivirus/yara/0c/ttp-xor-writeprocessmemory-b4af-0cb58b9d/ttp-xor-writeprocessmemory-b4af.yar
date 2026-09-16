rule TTP_XOR_WriteProcessMemory_b4af {
  strings:
    $key_b4af = { e3 dd [2] d1 ff [2] d7 ca [2] f9 ca [2] c6 d6 }

  condition:
    any of them
}