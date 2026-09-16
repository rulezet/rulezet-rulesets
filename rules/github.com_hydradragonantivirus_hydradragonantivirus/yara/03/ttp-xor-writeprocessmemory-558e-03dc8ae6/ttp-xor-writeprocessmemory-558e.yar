rule TTP_XOR_WriteProcessMemory_558e {
  strings:
    $key_558e = { 02 fc [2] 30 de [2] 36 eb [2] 18 eb [2] 27 f7 }

  condition:
    any of them
}