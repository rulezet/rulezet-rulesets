rule TTP_XOR_MULT_DOSStub_756c {
  strings:
    $key_756c = { 21 04 [2] 55 1c [2] 12 1e [2] 55 0f [2] 1b 03 [2] 17 09 [2] 00 02 [2] 1b 4c [2] 26 }

  condition:
    any of them
}