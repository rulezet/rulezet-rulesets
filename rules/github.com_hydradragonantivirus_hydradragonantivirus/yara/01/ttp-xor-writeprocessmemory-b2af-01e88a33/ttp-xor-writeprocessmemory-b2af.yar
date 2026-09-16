rule TTP_XOR_WriteProcessMemory_b2af {
  strings:
    $key_b2af = { e5 dd [2] d7 ff [2] d1 ca [2] ff ca [2] c0 d6 }

  condition:
    any of them
}