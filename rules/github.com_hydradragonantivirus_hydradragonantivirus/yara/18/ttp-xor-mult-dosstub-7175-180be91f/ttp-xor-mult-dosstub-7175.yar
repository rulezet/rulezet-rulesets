rule TTP_XOR_MULT_DOSStub_7175 {
  strings:
    $key_7175 = { 25 1d [2] 51 05 [2] 16 07 [2] 51 16 [2] 1f 1a [2] 13 10 [2] 04 1b [2] 1f 55 [2] 22 }

  condition:
    any of them
}