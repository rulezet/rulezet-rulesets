rule TTP_XOR_WriteProcessMemory_060e {
  strings:
    $key_060e = { 51 7c [2] 63 5e [2] 65 6b [2] 4b 6b [2] 74 77 }

  condition:
    any of them
}