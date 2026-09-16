rule TTP_XOR_WriteProcessMemory_cc8e {
  strings:
    $key_cc8e = { 9b fc [2] a9 de [2] af eb [2] 81 eb [2] be f7 }

  condition:
    any of them
}