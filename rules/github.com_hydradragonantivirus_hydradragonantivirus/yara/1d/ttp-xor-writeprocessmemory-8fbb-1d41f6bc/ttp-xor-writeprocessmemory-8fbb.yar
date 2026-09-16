rule TTP_XOR_WriteProcessMemory_8fbb {
  strings:
    $key_8fbb = { d8 c9 [2] ea eb [2] ec de [2] c2 de [2] fd c2 }

  condition:
    any of them
}