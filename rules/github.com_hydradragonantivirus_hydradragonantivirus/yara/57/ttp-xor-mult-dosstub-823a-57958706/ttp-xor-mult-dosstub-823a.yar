rule TTP_XOR_MULT_DOSStub_823a {
  strings:
    $key_823a = { d6 52 [2] a2 4a [2] e5 48 [2] a2 59 [2] ec 55 [2] e0 5f [2] f7 54 [2] ec 1a [2] d1 }

  condition:
    any of them
}