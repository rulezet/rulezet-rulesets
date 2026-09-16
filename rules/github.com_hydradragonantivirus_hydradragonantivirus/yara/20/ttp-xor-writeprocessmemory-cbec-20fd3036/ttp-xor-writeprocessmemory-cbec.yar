rule TTP_XOR_WriteProcessMemory_cbec {
  strings:
    $key_cbec = { 9c 9e [2] ae bc [2] a8 89 [2] 86 89 [2] b9 95 }

  condition:
    any of them
}