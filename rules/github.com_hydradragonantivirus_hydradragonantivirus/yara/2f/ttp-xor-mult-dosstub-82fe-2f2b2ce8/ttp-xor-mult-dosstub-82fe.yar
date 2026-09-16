rule TTP_XOR_MULT_DOSStub_82fe {
  strings:
    $key_82fe = { d6 96 [2] a2 8e [2] e5 8c [2] a2 9d [2] ec 91 [2] e0 9b [2] f7 90 [2] ec de [2] d1 }

  condition:
    any of them
}