rule TTP_XOR_MULT_DOSStub_cc8a {
  strings:
    $key_cc8a = { 98 e2 [2] ec fa [2] ab f8 [2] ec e9 [2] a2 e5 [2] ae ef [2] b9 e4 [2] a2 aa [2] 9f }

  condition:
    any of them
}