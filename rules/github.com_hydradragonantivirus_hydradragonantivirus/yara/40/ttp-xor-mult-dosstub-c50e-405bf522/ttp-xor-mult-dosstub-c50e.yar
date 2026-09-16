rule TTP_XOR_MULT_DOSStub_c50e {
  strings:
    $key_c50e = { 91 66 [2] e5 7e [2] a2 7c [2] e5 6d [2] ab 61 [2] a7 6b [2] b0 60 [2] ab 2e [2] 96 }

  condition:
    any of them
}