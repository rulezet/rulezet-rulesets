rule TTP_XOR_MULT_DOSStub_ee6d {
  strings:
    $key_ee6d = { ba 05 [2] ce 1d [2] 89 1f [2] ce 0e [2] 80 02 [2] 8c 08 [2] 9b 03 [2] 80 4d [2] bd }

  condition:
    any of them
}