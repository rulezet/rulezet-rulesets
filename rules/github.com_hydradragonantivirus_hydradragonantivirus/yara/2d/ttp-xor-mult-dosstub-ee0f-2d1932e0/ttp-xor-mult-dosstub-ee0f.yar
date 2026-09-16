rule TTP_XOR_MULT_DOSStub_ee0f {
  strings:
    $key_ee0f = { ba 67 [2] ce 7f [2] 89 7d [2] ce 6c [2] 80 60 [2] 8c 6a [2] 9b 61 [2] 80 2f [2] bd }

  condition:
    any of them
}