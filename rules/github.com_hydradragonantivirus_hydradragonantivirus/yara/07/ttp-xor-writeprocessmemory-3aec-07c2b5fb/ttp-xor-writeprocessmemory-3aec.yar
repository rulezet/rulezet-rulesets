rule TTP_XOR_WriteProcessMemory_3aec {
  strings:
    $key_3aec = { 6d 9e [2] 5f bc [2] 59 89 [2] 77 89 [2] 48 95 }

  condition:
    any of them
}