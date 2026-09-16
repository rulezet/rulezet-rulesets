rule TTP_XOR_MULT_DOSStub_940f {
  strings:
    $key_940f = { c0 67 [2] b4 7f [2] f3 7d [2] b4 6c [2] fa 60 [2] f6 6a [2] e1 61 [2] fa 2f [2] c7 }

  condition:
    any of them
}