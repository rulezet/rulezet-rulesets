rule TTP_XOR_WriteProcessMemory_a0af {
  strings:
    $key_a0af = { f7 dd [2] c5 ff [2] c3 ca [2] ed ca [2] d2 d6 }

  condition:
    any of them
}