rule TTP_XOR_MULT_DOSStub_5738 {
  strings:
    $key_5738 = { 03 50 [2] 77 48 [2] 30 4a [2] 77 5b [2] 39 57 [2] 35 5d [2] 22 56 [2] 39 18 [2] 04 }

  condition:
    any of them
}