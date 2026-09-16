rule TTP_XOR_WriteProcessMemory_de8e {
  strings:
    $key_de8e = { 89 fc [2] bb de [2] bd eb [2] 93 eb [2] ac f7 }

  condition:
    any of them
}