rule TTP_XOR_MULT_DOSStub_823d {
  strings:
    $key_823d = { d6 55 [2] a2 4d [2] e5 4f [2] a2 5e [2] ec 52 [2] e0 58 [2] f7 53 [2] ec 1d [2] d1 }

  condition:
    any of them
}