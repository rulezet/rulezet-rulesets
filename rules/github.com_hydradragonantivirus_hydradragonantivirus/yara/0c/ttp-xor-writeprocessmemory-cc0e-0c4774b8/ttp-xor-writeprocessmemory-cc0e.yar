rule TTP_XOR_WriteProcessMemory_cc0e {
  strings:
    $key_cc0e = { 9b 7c [2] a9 5e [2] af 6b [2] 81 6b [2] be 77 }

  condition:
    any of them
}