rule TTP_XOR_MULT_DOSStub_888a {
  strings:
    $key_888a = { dc e2 [2] a8 fa [2] ef f8 [2] a8 e9 [2] e6 e5 [2] ea ef [2] fd e4 [2] e6 aa [2] db }

  condition:
    any of them
}