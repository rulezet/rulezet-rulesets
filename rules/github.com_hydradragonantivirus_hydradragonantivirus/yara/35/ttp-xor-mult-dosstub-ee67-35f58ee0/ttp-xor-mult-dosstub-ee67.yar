rule TTP_XOR_MULT_DOSStub_ee67 {
  strings:
    $key_ee67 = { ba 0f [2] ce 17 [2] 89 15 [2] ce 04 [2] 80 08 [2] 8c 02 [2] 9b 09 [2] 80 47 [2] bd }

  condition:
    any of them
}