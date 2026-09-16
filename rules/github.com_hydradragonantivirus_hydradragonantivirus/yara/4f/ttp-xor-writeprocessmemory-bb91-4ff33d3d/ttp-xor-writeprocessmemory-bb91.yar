rule TTP_XOR_WriteProcessMemory_bb91 {
  strings:
    $key_bb91 = { ec e3 [2] de c1 [2] d8 f4 [2] f6 f4 [2] c9 e8 }

  condition:
    any of them
}