rule TTP_XOR_MULT_DOSStub_8857 {
  strings:
    $key_8857 = { dc 3f [2] a8 27 [2] ef 25 [2] a8 34 [2] e6 38 [2] ea 32 [2] fd 39 [2] e6 77 [2] db }

  condition:
    any of them
}