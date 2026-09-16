rule TTP_XOR_WriteProcessMemory_3e6c {
  strings:
    $key_3e6c = { 69 1e [2] 5b 3c [2] 5d 09 [2] 73 09 [2] 4c 15 }

  condition:
    any of them
}