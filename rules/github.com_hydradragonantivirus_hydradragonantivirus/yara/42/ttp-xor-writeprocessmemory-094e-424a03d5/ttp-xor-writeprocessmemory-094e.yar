rule TTP_XOR_WriteProcessMemory_094e {
  strings:
    $key_094e = { 5e 3c [2] 6c 1e [2] 6a 2b [2] 44 2b [2] 7b 37 }

  condition:
    any of them
}