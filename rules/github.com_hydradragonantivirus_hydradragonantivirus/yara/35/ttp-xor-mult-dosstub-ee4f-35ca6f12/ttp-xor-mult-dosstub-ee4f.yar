rule TTP_XOR_MULT_DOSStub_ee4f {
  strings:
    $key_ee4f = { ba 27 [2] ce 3f [2] 89 3d [2] ce 2c [2] 80 20 [2] 8c 2a [2] 9b 21 [2] 80 6f [2] bd }

  condition:
    any of them
}