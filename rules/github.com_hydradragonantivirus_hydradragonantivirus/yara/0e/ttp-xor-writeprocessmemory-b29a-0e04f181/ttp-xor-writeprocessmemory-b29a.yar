rule TTP_XOR_WriteProcessMemory_b29a {
  strings:
    $key_b29a = { e5 e8 [2] d7 ca [2] d1 ff [2] ff ff [2] c0 e3 }

  condition:
    any of them
}