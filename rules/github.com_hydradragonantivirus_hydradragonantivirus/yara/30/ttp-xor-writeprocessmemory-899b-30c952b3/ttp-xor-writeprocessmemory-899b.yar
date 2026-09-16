rule TTP_XOR_WriteProcessMemory_899b {
  strings:
    $key_899b = { de e9 [2] ec cb [2] ea fe [2] c4 fe [2] fb e2 }

  condition:
    any of them
}