rule TTP_XOR_MULT_DOSStub_889d {
  strings:
    $key_889d = { dc f5 [2] a8 ed [2] ef ef [2] a8 fe [2] e6 f2 [2] ea f8 [2] fd f3 [2] e6 bd [2] db }

  condition:
    any of them
}