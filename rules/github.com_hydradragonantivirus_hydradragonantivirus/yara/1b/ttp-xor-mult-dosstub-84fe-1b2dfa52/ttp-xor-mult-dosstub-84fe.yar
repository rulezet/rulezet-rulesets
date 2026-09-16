rule TTP_XOR_MULT_DOSStub_84fe {
  strings:
    $key_84fe = { d0 96 [2] a4 8e [2] e3 8c [2] a4 9d [2] ea 91 [2] e6 9b [2] f1 90 [2] ea de [2] d7 }

  condition:
    any of them
}