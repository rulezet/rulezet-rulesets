rule TTP_XOR_MULT_DOSStub_942b {
  strings:
    $key_942b = { c0 43 [2] b4 5b [2] f3 59 [2] b4 48 [2] fa 44 [2] f6 4e [2] e1 45 [2] fa 0b [2] c7 }

  condition:
    any of them
}