rule TTP_XOR_WriteProcessMemory_bcc5 {
  strings:
    $key_bcc5 = { eb b7 [2] d9 95 [2] df a0 [2] f1 a0 [2] ce bc }

  condition:
    any of them
}