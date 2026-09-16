rule TTP_XOR_WriteProcessMemory_bccb {
  strings:
    $key_bccb = { eb b9 [2] d9 9b [2] df ae [2] f1 ae [2] ce b2 }

  condition:
    any of them
}