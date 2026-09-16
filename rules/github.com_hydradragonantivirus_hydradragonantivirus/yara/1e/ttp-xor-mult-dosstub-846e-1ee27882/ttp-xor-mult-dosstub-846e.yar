rule TTP_XOR_MULT_DOSStub_846e {
  strings:
    $key_846e = { d0 06 [2] a4 1e [2] e3 1c [2] a4 0d [2] ea 01 [2] e6 0b [2] f1 00 [2] ea 4e [2] d7 }

  condition:
    any of them
}