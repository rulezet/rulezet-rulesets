rule TTP_XOR_MULT_DOSStub_32dd {
  strings:
    $key_32dd = { 66 b5 [2] 12 ad [2] 55 af [2] 12 be [2] 5c b2 [2] 50 b8 [2] 47 b3 [2] 5c fd [2] 61 }

  condition:
    any of them
}