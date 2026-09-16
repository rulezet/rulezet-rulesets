rule TTP_XOR_WriteProcessMemory_536c {
  strings:
    $key_536c = { 04 1e [2] 36 3c [2] 30 09 [2] 1e 09 [2] 21 15 }

  condition:
    any of them
}