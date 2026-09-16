rule TTP_XOR_MULT_DOSStub_d30e {
  strings:
    $key_d30e = { 87 66 [2] f3 7e [2] b4 7c [2] f3 6d [2] bd 61 [2] b1 6b [2] a6 60 [2] bd 2e [2] 80 }

  condition:
    any of them
}