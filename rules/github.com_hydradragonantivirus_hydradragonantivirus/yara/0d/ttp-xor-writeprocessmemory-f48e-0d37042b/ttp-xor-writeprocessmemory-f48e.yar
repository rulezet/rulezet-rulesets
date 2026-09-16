rule TTP_XOR_WriteProcessMemory_f48e {
  strings:
    $key_f48e = { a3 fc [2] 91 de [2] 97 eb [2] b9 eb [2] 86 f7 }

  condition:
    any of them
}