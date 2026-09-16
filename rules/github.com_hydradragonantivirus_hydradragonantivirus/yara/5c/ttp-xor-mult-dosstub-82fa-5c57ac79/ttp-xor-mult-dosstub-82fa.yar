rule TTP_XOR_MULT_DOSStub_82fa {
  strings:
    $key_82fa = { d6 92 [2] a2 8a [2] e5 88 [2] a2 99 [2] ec 95 [2] e0 9f [2] f7 94 [2] ec da [2] d1 }

  condition:
    any of them
}