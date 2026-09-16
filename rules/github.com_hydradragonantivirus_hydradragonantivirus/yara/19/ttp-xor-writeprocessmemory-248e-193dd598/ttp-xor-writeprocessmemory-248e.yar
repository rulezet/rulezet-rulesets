rule TTP_XOR_WriteProcessMemory_248e {
  strings:
    $key_248e = { 73 fc [2] 41 de [2] 47 eb [2] 69 eb [2] 56 f7 }

  condition:
    any of them
}