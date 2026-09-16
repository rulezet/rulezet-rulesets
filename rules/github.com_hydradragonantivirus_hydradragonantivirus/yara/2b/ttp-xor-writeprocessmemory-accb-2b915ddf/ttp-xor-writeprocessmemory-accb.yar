rule TTP_XOR_WriteProcessMemory_accb {
  strings:
    $key_accb = { fb b9 [2] c9 9b [2] cf ae [2] e1 ae [2] de b2 }

  condition:
    any of them
}