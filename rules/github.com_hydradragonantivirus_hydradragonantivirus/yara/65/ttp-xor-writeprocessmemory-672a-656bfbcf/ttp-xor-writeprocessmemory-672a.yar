rule TTP_XOR_WriteProcessMemory_672a {
  strings:
    $key_672a = { 30 58 [2] 02 7a [2] 04 4f [2] 2a 4f [2] 15 53 }

  condition:
    any of them
}