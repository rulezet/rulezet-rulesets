rule TTP_XOR_WriteProcessMemory_b49a {
  strings:
    $key_b49a = { e3 e8 [2] d1 ca [2] d7 ff [2] f9 ff [2] c6 e3 }

  condition:
    any of them
}