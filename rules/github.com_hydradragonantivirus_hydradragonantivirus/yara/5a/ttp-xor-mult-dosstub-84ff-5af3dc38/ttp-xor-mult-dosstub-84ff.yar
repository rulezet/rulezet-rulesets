rule TTP_XOR_MULT_DOSStub_84ff {
  strings:
    $key_84ff = { d0 97 [2] a4 8f [2] e3 8d [2] a4 9c [2] ea 90 [2] e6 9a [2] f1 91 [2] ea df [2] d7 }

  condition:
    any of them
}