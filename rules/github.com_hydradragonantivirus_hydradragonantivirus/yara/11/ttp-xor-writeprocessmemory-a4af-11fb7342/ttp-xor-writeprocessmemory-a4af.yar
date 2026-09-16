rule TTP_XOR_WriteProcessMemory_a4af {
  strings:
    $key_a4af = { f3 dd [2] c1 ff [2] c7 ca [2] e9 ca [2] d6 d6 }

  condition:
    any of them
}