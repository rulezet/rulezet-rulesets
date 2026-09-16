rule TTP_XOR_MULT_DOSStub_ee2f {
  strings:
    $key_ee2f = { ba 47 [2] ce 5f [2] 89 5d [2] ce 4c [2] 80 40 [2] 8c 4a [2] 9b 41 [2] 80 0f [2] bd }

  condition:
    any of them
}