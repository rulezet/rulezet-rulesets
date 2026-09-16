rule TTP_XOR_WriteProcessMemory_4b3e {
  strings:
    $key_4b3e = { 1c 4c [2] 2e 6e [2] 28 5b [2] 06 5b [2] 39 47 }

  condition:
    any of them
}