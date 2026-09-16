rule TTP_XOR_MULT_DOSStub_573d {
  strings:
    $key_573d = { 03 55 [2] 77 4d [2] 30 4f [2] 77 5e [2] 39 52 [2] 35 58 [2] 22 53 [2] 39 1d [2] 04 }

  condition:
    any of them
}