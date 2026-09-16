rule TTP_XOR_MULT_DOSStub_ee0d {
  strings:
    $key_ee0d = { ba 65 [2] ce 7d [2] 89 7f [2] ce 6e [2] 80 62 [2] 8c 68 [2] 9b 63 [2] 80 2d [2] bd }

  condition:
    any of them
}