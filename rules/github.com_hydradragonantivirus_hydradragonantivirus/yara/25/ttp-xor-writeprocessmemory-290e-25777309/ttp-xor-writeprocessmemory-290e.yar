rule TTP_XOR_WriteProcessMemory_290e {
  strings:
    $key_290e = { 7e 7c [2] 4c 5e [2] 4a 6b [2] 64 6b [2] 5b 77 }

  condition:
    any of them
}