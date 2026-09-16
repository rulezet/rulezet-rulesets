rule TTP_XOR_MULT_DOSStub_ee6a {
  strings:
    $key_ee6a = { ba 02 [2] ce 1a [2] 89 18 [2] ce 09 [2] 80 05 [2] 8c 0f [2] 9b 04 [2] 80 4a [2] bd }

  condition:
    any of them
}