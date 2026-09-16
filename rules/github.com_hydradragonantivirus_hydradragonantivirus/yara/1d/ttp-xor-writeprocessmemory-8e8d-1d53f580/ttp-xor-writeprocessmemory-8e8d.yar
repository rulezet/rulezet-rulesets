rule TTP_XOR_WriteProcessMemory_8e8d {
  strings:
    $key_8e8d = { d9 ff [2] eb dd [2] ed e8 [2] c3 e8 [2] fc f4 }

  condition:
    any of them
}