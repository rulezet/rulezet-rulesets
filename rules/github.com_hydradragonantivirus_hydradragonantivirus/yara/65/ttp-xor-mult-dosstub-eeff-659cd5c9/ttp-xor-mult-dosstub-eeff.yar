rule TTP_XOR_MULT_DOSStub_eeff {
  strings:
    $key_eeff = { ba 97 [2] ce 8f [2] 89 8d [2] ce 9c [2] 80 90 [2] 8c 9a [2] 9b 91 [2] 80 df [2] bd }

  condition:
    any of them
}