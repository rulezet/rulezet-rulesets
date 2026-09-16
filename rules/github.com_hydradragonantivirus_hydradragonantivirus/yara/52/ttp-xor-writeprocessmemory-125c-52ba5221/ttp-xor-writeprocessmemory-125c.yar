rule TTP_XOR_WriteProcessMemory_125c {
  strings:
    $key_125c = { 45 2e [2] 77 0c [2] 71 39 [2] 5f 39 [2] 60 25 }

  condition:
    any of them
}