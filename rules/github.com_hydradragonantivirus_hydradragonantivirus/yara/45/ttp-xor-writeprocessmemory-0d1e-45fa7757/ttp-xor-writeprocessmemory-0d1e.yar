rule TTP_XOR_WriteProcessMemory_0d1e {
  strings:
    $key_0d1e = { 5a 6c [2] 68 4e [2] 6e 7b [2] 40 7b [2] 7f 67 }

  condition:
    any of them
}