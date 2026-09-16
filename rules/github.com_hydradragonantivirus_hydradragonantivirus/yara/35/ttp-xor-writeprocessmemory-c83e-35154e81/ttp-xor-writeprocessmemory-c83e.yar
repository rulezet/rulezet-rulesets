rule TTP_XOR_WriteProcessMemory_c83e {
  strings:
    $key_c83e = { 9f 4c [2] ad 6e [2] ab 5b [2] 85 5b [2] ba 47 }

  condition:
    any of them
}