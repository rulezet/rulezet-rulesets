rule TTP_XOR_WriteProcessMemory_121e {
  strings:
    $key_121e = { 45 6c [2] 77 4e [2] 71 7b [2] 5f 7b [2] 60 67 }

  condition:
    any of them
}