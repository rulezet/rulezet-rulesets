rule TTP_XOR_WriteProcessMemory_aa39 {
  strings:
    $key_aa39 = { fd 4b [2] cf 69 [2] c9 5c [2] e7 5c [2] d8 40 }

  condition:
    any of them
}