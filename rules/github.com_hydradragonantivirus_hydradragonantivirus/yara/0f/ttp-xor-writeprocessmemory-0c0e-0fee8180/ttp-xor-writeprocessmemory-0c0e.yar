rule TTP_XOR_WriteProcessMemory_0c0e {
  strings:
    $key_0c0e = { 5b 7c [2] 69 5e [2] 6f 6b [2] 41 6b [2] 7e 77 }

  condition:
    any of them
}