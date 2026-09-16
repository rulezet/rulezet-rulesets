rule TTP_XOR_WriteProcessMemory_691e {
  strings:
    $key_691e = { 3e 6c [2] 0c 4e [2] 0a 7b [2] 24 7b [2] 1b 67 }

  condition:
    any of them
}