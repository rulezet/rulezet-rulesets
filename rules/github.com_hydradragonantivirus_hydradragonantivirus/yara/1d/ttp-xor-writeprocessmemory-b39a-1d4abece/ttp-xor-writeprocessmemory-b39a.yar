rule TTP_XOR_WriteProcessMemory_b39a {
  strings:
    $key_b39a = { e4 e8 [2] d6 ca [2] d0 ff [2] fe ff [2] c1 e3 }

  condition:
    any of them
}