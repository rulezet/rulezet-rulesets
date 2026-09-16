rule TTP_XOR_MULT_DOSStub_972f {
  strings:
    $key_972f = { c3 47 [2] b7 5f [2] f0 5d [2] b7 4c [2] f9 40 [2] f5 4a [2] e2 41 [2] f9 0f [2] c4 }

  condition:
    any of them
}