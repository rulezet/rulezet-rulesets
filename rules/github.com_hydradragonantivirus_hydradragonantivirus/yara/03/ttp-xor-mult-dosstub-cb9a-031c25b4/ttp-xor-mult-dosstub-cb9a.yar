rule TTP_XOR_MULT_DOSStub_cb9a {
  strings:
    $key_cb9a = { 9f f2 [2] eb ea [2] ac e8 [2] eb f9 [2] a5 f5 [2] a9 ff [2] be f4 [2] a5 ba [2] 98 }

  condition:
    any of them
}