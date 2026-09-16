rule TTP_XOR_WriteProcessMemory_aa5c {
  strings:
    $key_aa5c = { fd 2e [2] cf 0c [2] c9 39 [2] e7 39 [2] d8 25 }

  condition:
    any of them
}