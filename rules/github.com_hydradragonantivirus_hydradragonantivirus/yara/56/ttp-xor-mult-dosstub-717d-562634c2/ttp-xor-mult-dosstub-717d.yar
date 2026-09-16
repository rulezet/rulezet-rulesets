rule TTP_XOR_MULT_DOSStub_717d {
  strings:
    $key_717d = { 25 15 [2] 51 0d [2] 16 0f [2] 51 1e [2] 1f 12 [2] 13 18 [2] 04 13 [2] 1f 5d [2] 22 }

  condition:
    any of them
}