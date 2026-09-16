rule TTP_XOR_WriteProcessMemory_942c {
  strings:
    $key_942c = { c3 5e [2] f1 7c [2] f7 49 [2] d9 49 [2] e6 55 }

  condition:
    any of them
}