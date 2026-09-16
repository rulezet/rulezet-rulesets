rule TTP_XOR_WriteProcessMemory_ccdc {
  strings:
    $key_ccdc = { 9b ae [2] a9 8c [2] af b9 [2] 81 b9 [2] be a5 }

  condition:
    any of them
}