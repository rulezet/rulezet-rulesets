rule TTP_XOR_WriteProcessMemory_aa1c {
  strings:
    $key_aa1c = { fd 6e [2] cf 4c [2] c9 79 [2] e7 79 [2] d8 65 }

  condition:
    any of them
}