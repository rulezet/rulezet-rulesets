rule TTP_XOR_WriteProcessMemory_690e {
  strings:
    $key_690e = { 3e 7c [2] 0c 5e [2] 0a 6b [2] 24 6b [2] 1b 77 }

  condition:
    any of them
}