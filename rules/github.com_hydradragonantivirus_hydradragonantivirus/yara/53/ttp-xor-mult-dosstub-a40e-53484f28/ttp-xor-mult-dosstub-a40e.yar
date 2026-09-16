rule TTP_XOR_MULT_DOSStub_a40e {
  strings:
    $key_a40e = { f0 66 [2] 84 7e [2] c3 7c [2] 84 6d [2] ca 61 [2] c6 6b [2] d1 60 [2] ca 2e [2] f7 }

  condition:
    any of them
}