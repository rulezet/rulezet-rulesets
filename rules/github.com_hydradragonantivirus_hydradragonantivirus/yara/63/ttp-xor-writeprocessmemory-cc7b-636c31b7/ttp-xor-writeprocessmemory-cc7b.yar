rule TTP_XOR_WriteProcessMemory_cc7b {
  strings:
    $key_cc7b = { 9b 09 [2] a9 2b [2] af 1e [2] 81 1e [2] be 02 }

  condition:
    any of them
}