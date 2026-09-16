rule TTP_XOR_WriteProcessMemory_8eaf {
  strings:
    $key_8eaf = { d9 dd [2] eb ff [2] ed ca [2] c3 ca [2] fc d6 }

  condition:
    any of them
}