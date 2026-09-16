rule TTP_XOR_MULT_DOSStub_6b68 {
  strings:
    $key_6b68 = { 3f 00 [2] 4b 18 [2] 0c 1a [2] 4b 0b [2] 05 07 [2] 09 0d [2] 1e 06 [2] 05 48 [2] 38 }

  condition:
    any of them
}