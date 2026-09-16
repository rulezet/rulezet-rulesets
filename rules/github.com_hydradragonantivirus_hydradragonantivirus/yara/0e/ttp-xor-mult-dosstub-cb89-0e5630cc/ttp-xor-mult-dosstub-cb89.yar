rule TTP_XOR_MULT_DOSStub_cb89 {
  strings:
    $key_cb89 = { 9f e1 [2] eb f9 [2] ac fb [2] eb ea [2] a5 e6 [2] a9 ec [2] be e7 [2] a5 a9 [2] 98 }

  condition:
    any of them
}