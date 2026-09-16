rule TTP_XOR_WriteProcessMemory_b42c {
  strings:
    $key_b42c = { e3 5e [2] d1 7c [2] d7 49 [2] f9 49 [2] c6 55 }

  condition:
    any of them
}