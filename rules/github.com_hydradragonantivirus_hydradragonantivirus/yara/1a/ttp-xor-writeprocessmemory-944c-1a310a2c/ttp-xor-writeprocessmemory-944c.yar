rule TTP_XOR_WriteProcessMemory_944c {
  strings:
    $key_944c = { c3 3e [2] f1 1c [2] f7 29 [2] d9 29 [2] e6 35 }

  condition:
    any of them
}