rule TTP_XOR_MULT_DOSStub_943b {
  strings:
    $key_943b = { c0 53 [2] b4 4b [2] f3 49 [2] b4 58 [2] fa 54 [2] f6 5e [2] e1 55 [2] fa 1b [2] c7 }

  condition:
    any of them
}