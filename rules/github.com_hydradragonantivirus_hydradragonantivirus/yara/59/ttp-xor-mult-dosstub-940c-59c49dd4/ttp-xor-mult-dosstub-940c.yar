rule TTP_XOR_MULT_DOSStub_940c {
  strings:
    $key_940c = { c0 64 [2] b4 7c [2] f3 7e [2] b4 6f [2] fa 63 [2] f6 69 [2] e1 62 [2] fa 2c [2] c7 }

  condition:
    any of them
}