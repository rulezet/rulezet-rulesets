rule TTP_XOR_WriteProcessMemory_cc6c {
  strings:
    $key_cc6c = { 9b 1e [2] a9 3c [2] af 09 [2] 81 09 [2] be 15 }

  condition:
    any of them
}