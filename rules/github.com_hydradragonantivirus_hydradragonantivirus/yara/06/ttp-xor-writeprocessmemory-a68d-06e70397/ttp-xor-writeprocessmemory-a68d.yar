rule TTP_XOR_WriteProcessMemory_a68d {
  strings:
    $key_a68d = { f1 ff [2] c3 dd [2] c5 e8 [2] eb e8 [2] d4 f4 }

  condition:
    any of them
}