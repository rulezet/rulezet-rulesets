rule TTP_XOR_MULT_DOSStub_d70e {
  strings:
    $key_d70e = { 83 66 [2] f7 7e [2] b0 7c [2] f7 6d [2] b9 61 [2] b5 6b [2] a2 60 [2] b9 2e [2] 84 }

  condition:
    any of them
}