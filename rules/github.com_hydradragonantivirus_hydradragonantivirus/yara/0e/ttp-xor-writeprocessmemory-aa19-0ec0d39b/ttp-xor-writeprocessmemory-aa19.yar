rule TTP_XOR_WriteProcessMemory_aa19 {
  strings:
    $key_aa19 = { fd 6b [2] cf 49 [2] c9 7c [2] e7 7c [2] d8 60 }

  condition:
    any of them
}