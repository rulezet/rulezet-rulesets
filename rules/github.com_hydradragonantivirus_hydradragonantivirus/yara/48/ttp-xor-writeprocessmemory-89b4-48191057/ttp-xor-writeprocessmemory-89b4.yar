rule TTP_XOR_WriteProcessMemory_89b4 {
  strings:
    $key_89b4 = { de c6 [2] ec e4 [2] ea d1 [2] c4 d1 [2] fb cd }

  condition:
    any of them
}