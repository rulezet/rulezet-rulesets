rule TTP_XOR_WriteProcessMemory_cc1e {
  strings:
    $key_cc1e = { 9b 6c [2] a9 4e [2] af 7b [2] 81 7b [2] be 67 }

  condition:
    any of them
}