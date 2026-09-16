rule TTP_XOR_WriteProcessMemory_ac8e {
  strings:
    $key_ac8e = { fb fc [2] c9 de [2] cf eb [2] e1 eb [2] de f7 }

  condition:
    any of them
}