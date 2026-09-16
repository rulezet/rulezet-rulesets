rule TTP_XOR_MULT_DOSStub_93fe {
  strings:
    $key_93fe = { c7 96 [2] b3 8e [2] f4 8c [2] b3 9d [2] fd 91 [2] f1 9b [2] e6 90 [2] fd de [2] c0 }

  condition:
    any of them
}