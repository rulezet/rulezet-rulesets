rule TTP_XOR_MULT_DOSStub_9412 {
  strings:
    $key_9412 = { c0 7a [2] b4 62 [2] f3 60 [2] b4 71 [2] fa 7d [2] f6 77 [2] e1 7c [2] fa 32 [2] c7 }

  condition:
    any of them
}