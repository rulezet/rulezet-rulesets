rule TTP_XOR_MULT_DOSStub_8262 {
  strings:
    $key_8262 = { d6 0a [2] a2 12 [2] e5 10 [2] a2 01 [2] ec 0d [2] e0 07 [2] f7 0c [2] ec 42 [2] d1 }

  condition:
    any of them
}