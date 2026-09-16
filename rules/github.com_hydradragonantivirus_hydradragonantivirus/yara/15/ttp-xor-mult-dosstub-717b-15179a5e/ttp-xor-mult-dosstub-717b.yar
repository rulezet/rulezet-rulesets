rule TTP_XOR_MULT_DOSStub_717b {
  strings:
    $key_717b = { 25 13 [2] 51 0b [2] 16 09 [2] 51 18 [2] 1f 14 [2] 13 1e [2] 04 15 [2] 1f 5b [2] 22 }

  condition:
    any of them
}