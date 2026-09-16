rule TTP_XOR_WriteProcessMemory_aa09 {
  strings:
    $key_aa09 = { fd 7b [2] cf 59 [2] c9 6c [2] e7 6c [2] d8 70 }

  condition:
    any of them
}