rule TTP_XOR_MULT_DOSStub_3e68 {
  strings:
    $key_3e68 = { 6a 00 [2] 1e 18 [2] 59 1a [2] 1e 0b [2] 50 07 [2] 5c 0d [2] 4b 06 [2] 50 48 [2] 6d }

  condition:
    any of them
}