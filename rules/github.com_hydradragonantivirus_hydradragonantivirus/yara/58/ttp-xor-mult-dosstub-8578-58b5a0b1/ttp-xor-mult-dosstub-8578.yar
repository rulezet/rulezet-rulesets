rule TTP_XOR_MULT_DOSStub_8578 {
  strings:
    $key_8578 = { d1 10 [2] a5 08 [2] e2 0a [2] a5 1b [2] eb 17 [2] e7 1d [2] f0 16 [2] eb 58 [2] d6 }

  condition:
    any of them
}