rule TTP_XOR_MULT_DOSStub_8266 {
  strings:
    $key_8266 = { d6 0e [2] a2 16 [2] e5 14 [2] a2 05 [2] ec 09 [2] e0 03 [2] f7 08 [2] ec 46 [2] d1 }

  condition:
    any of them
}