rule TTP_XOR_WriteProcessMemory_391e {
  strings:
    $key_391e = { 6e 6c [2] 5c 4e [2] 5a 7b [2] 74 7b [2] 4b 67 }

  condition:
    any of them
}