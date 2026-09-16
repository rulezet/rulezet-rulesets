rule TTP_XOR_WriteProcessMemory_ccec {
  strings:
    $key_ccec = { 9b 9e [2] a9 bc [2] af 89 [2] 81 89 [2] be 95 }

  condition:
    any of them
}