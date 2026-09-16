rule TTP_XOR_WriteProcessMemory_a49a {
  strings:
    $key_a49a = { f3 e8 [2] c1 ca [2] c7 ff [2] e9 ff [2] d6 e3 }

  condition:
    any of them
}