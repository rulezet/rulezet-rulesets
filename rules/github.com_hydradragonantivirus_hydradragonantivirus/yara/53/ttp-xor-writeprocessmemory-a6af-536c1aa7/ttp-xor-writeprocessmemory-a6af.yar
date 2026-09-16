rule TTP_XOR_WriteProcessMemory_a6af {
  strings:
    $key_a6af = { f1 dd [2] c3 ff [2] c5 ca [2] eb ca [2] d4 d6 }

  condition:
    any of them
}