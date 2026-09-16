rule TTP_XOR_WriteProcessMemory_940c {
  strings:
    $key_940c = { c3 7e [2] f1 5c [2] f7 69 [2] d9 69 [2] e6 75 }

  condition:
    any of them
}