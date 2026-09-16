rule TTP_XOR_WriteProcessMemory_bcc1 {
  strings:
    $key_bcc1 = { eb b3 [2] d9 91 [2] df a4 [2] f1 a4 [2] ce b8 }

  condition:
    any of them
}