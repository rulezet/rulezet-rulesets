rule TTP_XOR_WriteProcessMemory_8f8e {
  strings:
    $key_8f8e = { d8 fc [2] ea de [2] ec eb [2] c2 eb [2] fd f7 }

  condition:
    any of them
}