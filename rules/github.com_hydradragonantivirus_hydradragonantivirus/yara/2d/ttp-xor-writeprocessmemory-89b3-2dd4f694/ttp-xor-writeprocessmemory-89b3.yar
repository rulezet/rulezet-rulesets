rule TTP_XOR_WriteProcessMemory_89b3 {
  strings:
    $key_89b3 = { de c1 [2] ec e3 [2] ea d6 [2] c4 d6 [2] fb ca }

  condition:
    any of them
}