rule TTP_XOR_WriteProcessMemory_796c {
  strings:
    $key_796c = { 2e 1e [2] 1c 3c [2] 1a 09 [2] 34 09 [2] 0b 15 }

  condition:
    any of them
}