rule TTP_XOR_WriteProcessMemory_8faf {
  strings:
    $key_8faf = { d8 dd [2] ea ff [2] ec ca [2] c2 ca [2] fd d6 }

  condition:
    any of them
}