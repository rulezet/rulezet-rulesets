rule TTP_XOR_WriteProcessMemory_692c {
  strings:
    $key_692c = { 3e 5e [2] 0c 7c [2] 0a 49 [2] 24 49 [2] 1b 55 }

  condition:
    any of them
}