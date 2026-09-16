rule TTP_XOR_WriteProcessMemory_3aee {
  strings:
    $key_3aee = { 6d 9c [2] 5f be [2] 59 8b [2] 77 8b [2] 48 97 }

  condition:
    any of them
}