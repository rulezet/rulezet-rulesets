rule TTP_XOR_WriteProcessMemory_c58e {
  strings:
    $key_c58e = { 92 fc [2] a0 de [2] a6 eb [2] 88 eb [2] b7 f7 }

  condition:
    any of them
}