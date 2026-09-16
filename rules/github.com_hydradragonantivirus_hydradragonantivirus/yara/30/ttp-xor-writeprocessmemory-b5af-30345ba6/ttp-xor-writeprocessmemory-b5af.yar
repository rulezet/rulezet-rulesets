rule TTP_XOR_WriteProcessMemory_b5af {
  strings:
    $key_b5af = { e2 dd [2] d0 ff [2] d6 ca [2] f8 ca [2] c7 d6 }

  condition:
    any of them
}