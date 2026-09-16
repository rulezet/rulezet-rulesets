rule TTP_XOR_WriteProcessMemory_c78e {
  strings:
    $key_c78e = { 90 fc [2] a2 de [2] a4 eb [2] 8a eb [2] b5 f7 }

  condition:
    any of them
}