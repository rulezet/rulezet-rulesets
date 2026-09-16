rule TTP_XOR_WriteProcessMemory_e48e {
  strings:
    $key_e48e = { b3 fc [2] 81 de [2] 87 eb [2] a9 eb [2] 96 f7 }

  condition:
    any of them
}