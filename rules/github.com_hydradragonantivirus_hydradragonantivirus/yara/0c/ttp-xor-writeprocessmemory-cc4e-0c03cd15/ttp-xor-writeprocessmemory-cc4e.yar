rule TTP_XOR_WriteProcessMemory_cc4e {
  strings:
    $key_cc4e = { 9b 3c [2] a9 1e [2] af 2b [2] 81 2b [2] be 37 }

  condition:
    any of them
}