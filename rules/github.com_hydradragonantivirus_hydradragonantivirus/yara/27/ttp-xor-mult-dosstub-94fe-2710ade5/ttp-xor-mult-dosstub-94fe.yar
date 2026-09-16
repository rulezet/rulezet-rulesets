rule TTP_XOR_MULT_DOSStub_94fe {
  strings:
    $key_94fe = { c0 96 [2] b4 8e [2] f3 8c [2] b4 9d [2] fa 91 [2] f6 9b [2] e1 90 [2] fa de [2] c7 }

  condition:
    any of them
}