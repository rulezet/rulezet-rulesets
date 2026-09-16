rule TTP_XOR_MULT_DOSStub_9f93 {
  strings:
    $key_9f93 = { cb fb [2] bf e3 [2] f8 e1 [2] bf f0 [2] f1 fc [2] fd f6 [2] ea fd [2] f1 b3 [2] cc }

  condition:
    any of them
}