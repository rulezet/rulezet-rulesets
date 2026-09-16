rule TTP_XOR_WriteProcessMemory_1c3e {
  strings:
    $key_1c3e = { 4b 4c [2] 79 6e [2] 7f 5b [2] 51 5b [2] 6e 47 }

  condition:
    any of them
}