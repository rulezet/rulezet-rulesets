rule TTP_XOR_WriteProcessMemory_d68e {
  strings:
    $key_d68e = { 81 fc [2] b3 de [2] b5 eb [2] 9b eb [2] a4 f7 }

  condition:
    any of them
}