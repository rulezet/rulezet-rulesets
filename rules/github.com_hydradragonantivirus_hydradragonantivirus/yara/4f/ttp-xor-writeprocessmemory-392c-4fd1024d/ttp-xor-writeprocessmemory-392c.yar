rule TTP_XOR_WriteProcessMemory_392c {
  strings:
    $key_392c = { 6e 5e [2] 5c 7c [2] 5a 49 [2] 74 49 [2] 4b 55 }

  condition:
    any of them
}