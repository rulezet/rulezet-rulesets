rule TTP_XOR_WriteProcessMemory_a09a {
  strings:
    $key_a09a = { f7 e8 [2] c5 ca [2] c3 ff [2] ed ff [2] d2 e3 }

  condition:
    any of them
}