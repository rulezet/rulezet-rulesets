rule TTP_XOR_MULT_DOSStub_949b {
  strings:
    $key_949b = { c0 f3 [2] b4 eb [2] f3 e9 [2] b4 f8 [2] fa f4 [2] f6 fe [2] e1 f5 [2] fa bb [2] c7 }

  condition:
    any of them
}