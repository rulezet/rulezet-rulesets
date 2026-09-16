rule TTP_XOR_WriteProcessMemory_a79a {
  strings:
    $key_a79a = { f0 e8 [2] c2 ca [2] c4 ff [2] ea ff [2] d5 e3 }

  condition:
    any of them
}