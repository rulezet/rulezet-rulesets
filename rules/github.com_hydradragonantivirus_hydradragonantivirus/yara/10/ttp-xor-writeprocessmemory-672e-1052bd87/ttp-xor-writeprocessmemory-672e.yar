rule TTP_XOR_WriteProcessMemory_672e {
  strings:
    $key_672e = { 30 5c [2] 02 7e [2] 04 4b [2] 2a 4b [2] 15 57 }

  condition:
    any of them
}