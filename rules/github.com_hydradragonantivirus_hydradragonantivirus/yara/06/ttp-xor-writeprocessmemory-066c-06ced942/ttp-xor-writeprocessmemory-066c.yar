rule TTP_XOR_WriteProcessMemory_066c {
  strings:
    $key_066c = { 51 1e [2] 63 3c [2] 65 09 [2] 4b 09 [2] 74 15 }

  condition:
    any of them
}