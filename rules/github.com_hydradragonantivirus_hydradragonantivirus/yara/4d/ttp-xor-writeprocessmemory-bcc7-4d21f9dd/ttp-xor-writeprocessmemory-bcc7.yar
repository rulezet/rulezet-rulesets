rule TTP_XOR_WriteProcessMemory_bcc7 {
  strings:
    $key_bcc7 = { eb b5 [2] d9 97 [2] df a2 [2] f1 a2 [2] ce be }

  condition:
    any of them
}