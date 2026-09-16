rule TTP_XOR_MULT_DOSStub_461f {
  strings:
    $key_461f = { 12 77 [2] 66 6f [2] 21 6d [2] 66 7c [2] 28 70 [2] 24 7a [2] 33 71 [2] 28 3f [2] 15 }

  condition:
    any of them
}