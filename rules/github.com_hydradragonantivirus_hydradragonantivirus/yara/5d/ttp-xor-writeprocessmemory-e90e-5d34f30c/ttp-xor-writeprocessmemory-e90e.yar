rule TTP_XOR_WriteProcessMemory_e90e {
  strings:
    $key_e90e = { be 7c [2] 8c 5e [2] 8a 6b [2] a4 6b [2] 9b 77 }

  condition:
    any of them
}