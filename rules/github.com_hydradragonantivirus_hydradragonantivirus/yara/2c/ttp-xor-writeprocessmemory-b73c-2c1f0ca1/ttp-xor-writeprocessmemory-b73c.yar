rule TTP_XOR_WriteProcessMemory_b73c {
  strings:
    $key_b73c = { e0 4e [2] d2 6c [2] d4 59 [2] fa 59 [2] c5 45 }

  condition:
    any of them
}