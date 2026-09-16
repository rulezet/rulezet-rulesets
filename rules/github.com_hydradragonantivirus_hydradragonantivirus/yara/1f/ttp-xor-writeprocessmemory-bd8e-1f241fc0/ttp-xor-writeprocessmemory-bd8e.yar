rule TTP_XOR_WriteProcessMemory_bd8e {
  strings:
    $key_bd8e = { ea fc [2] d8 de [2] de eb [2] f0 eb [2] cf f7 }

  condition:
    any of them
}