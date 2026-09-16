rule TTP_XOR_WriteProcessMemory_899a {
  strings:
    $key_899a = { de e8 [2] ec ca [2] ea ff [2] c4 ff [2] fb e3 }

  condition:
    any of them
}