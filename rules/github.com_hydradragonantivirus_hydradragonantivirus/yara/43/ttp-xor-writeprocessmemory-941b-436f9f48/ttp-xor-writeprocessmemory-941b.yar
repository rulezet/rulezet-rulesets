rule TTP_XOR_WriteProcessMemory_941b {
  strings:
    $key_941b = { c3 69 [2] f1 4b [2] f7 7e [2] d9 7e [2] e6 62 }

  condition:
    any of them
}