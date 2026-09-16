rule TTP_XOR_WriteProcessMemory_afcb {
  strings:
    $key_afcb = { f8 b9 [2] ca 9b [2] cc ae [2] e2 ae [2] dd b2 }

  condition:
    any of them
}