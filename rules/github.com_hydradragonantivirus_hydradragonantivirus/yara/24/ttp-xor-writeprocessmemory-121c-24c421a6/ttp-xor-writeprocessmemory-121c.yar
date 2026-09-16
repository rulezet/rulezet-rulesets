rule TTP_XOR_WriteProcessMemory_121c {
  strings:
    $key_121c = { 45 6e [2] 77 4c [2] 71 79 [2] 5f 79 [2] 60 65 }

  condition:
    any of them
}