rule TTP_XOR_WriteProcessMemory_a7af {
  strings:
    $key_a7af = { f0 dd [2] c2 ff [2] c4 ca [2] ea ca [2] d5 d6 }

  condition:
    any of them
}