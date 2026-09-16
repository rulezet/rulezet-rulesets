rule TTP_XOR_MULT_DOSStub_ee35 {
  strings:
    $key_ee35 = { ba 5d [2] ce 45 [2] 89 47 [2] ce 56 [2] 80 5a [2] 8c 50 [2] 9b 5b [2] 80 15 [2] bd }

  condition:
    any of them
}