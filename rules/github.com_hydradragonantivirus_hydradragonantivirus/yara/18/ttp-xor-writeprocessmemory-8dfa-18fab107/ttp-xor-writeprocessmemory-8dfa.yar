rule TTP_XOR_WriteProcessMemory_8dfa {
  strings:
    $key_8dfa = { da 88 [2] e8 aa [2] ee 9f [2] c0 9f [2] ff 83 }

  condition:
    any of them
}