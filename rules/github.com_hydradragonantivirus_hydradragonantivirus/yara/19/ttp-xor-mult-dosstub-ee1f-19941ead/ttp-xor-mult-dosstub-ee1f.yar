rule TTP_XOR_MULT_DOSStub_ee1f {
  strings:
    $key_ee1f = { ba 77 [2] ce 6f [2] 89 6d [2] ce 7c [2] 80 70 [2] 8c 7a [2] 9b 71 [2] 80 3f [2] bd }

  condition:
    any of them
}