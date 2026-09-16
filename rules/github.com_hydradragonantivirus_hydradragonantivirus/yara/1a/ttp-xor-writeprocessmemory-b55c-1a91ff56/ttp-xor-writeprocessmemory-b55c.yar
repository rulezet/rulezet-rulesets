rule TTP_XOR_WriteProcessMemory_b55c {
  strings:
    $key_b55c = { e2 2e [2] d0 0c [2] d6 39 [2] f8 39 [2] c7 25 }

  condition:
    any of them
}