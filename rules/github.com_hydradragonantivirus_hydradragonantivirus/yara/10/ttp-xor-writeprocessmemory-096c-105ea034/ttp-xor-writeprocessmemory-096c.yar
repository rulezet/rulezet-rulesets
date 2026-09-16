rule TTP_XOR_WriteProcessMemory_096c {
  strings:
    $key_096c = { 5e 1e [2] 6c 3c [2] 6a 09 [2] 44 09 [2] 7b 15 }

  condition:
    any of them
}