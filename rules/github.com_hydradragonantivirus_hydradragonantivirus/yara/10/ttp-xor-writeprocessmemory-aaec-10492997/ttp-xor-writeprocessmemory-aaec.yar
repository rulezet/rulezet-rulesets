rule TTP_XOR_WriteProcessMemory_aaec {
  strings:
    $key_aaec = { fd 9e [2] cf bc [2] c9 89 [2] e7 89 [2] d8 95 }

  condition:
    any of them
}