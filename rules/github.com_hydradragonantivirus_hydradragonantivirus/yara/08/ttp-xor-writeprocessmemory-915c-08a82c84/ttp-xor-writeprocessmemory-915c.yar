rule TTP_XOR_WriteProcessMemory_915c {
  strings:
    $key_915c = { c6 2e [2] f4 0c [2] f2 39 [2] dc 39 [2] e3 25 }

  condition:
    any of them
}