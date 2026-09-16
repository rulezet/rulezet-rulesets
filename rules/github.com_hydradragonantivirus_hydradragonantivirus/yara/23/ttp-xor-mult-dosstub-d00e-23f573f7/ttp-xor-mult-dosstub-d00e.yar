rule TTP_XOR_MULT_DOSStub_d00e {
  strings:
    $key_d00e = { 84 66 [2] f0 7e [2] b7 7c [2] f0 6d [2] be 61 [2] b2 6b [2] a5 60 [2] be 2e [2] 83 }

  condition:
    any of them
}