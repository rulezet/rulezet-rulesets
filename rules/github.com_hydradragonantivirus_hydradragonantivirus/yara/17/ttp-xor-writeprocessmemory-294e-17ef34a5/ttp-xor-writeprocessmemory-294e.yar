rule TTP_XOR_WriteProcessMemory_294e {
  strings:
    $key_294e = { 7e 3c [2] 4c 1e [2] 4a 2b [2] 64 2b [2] 5b 37 }

  condition:
    any of them
}