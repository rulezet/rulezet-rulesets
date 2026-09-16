rule TTP_XOR_WriteProcessMemory_dc8e {
  strings:
    $key_dc8e = { 8b fc [2] b9 de [2] bf eb [2] 91 eb [2] ae f7 }

  condition:
    any of them
}