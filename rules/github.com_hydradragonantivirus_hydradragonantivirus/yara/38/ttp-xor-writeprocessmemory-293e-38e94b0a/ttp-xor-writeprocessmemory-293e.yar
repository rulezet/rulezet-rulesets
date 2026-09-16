rule TTP_XOR_WriteProcessMemory_293e {
  strings:
    $key_293e = { 7e 4c [2] 4c 6e [2] 4a 5b [2] 64 5b [2] 5b 47 }

  condition:
    any of them
}