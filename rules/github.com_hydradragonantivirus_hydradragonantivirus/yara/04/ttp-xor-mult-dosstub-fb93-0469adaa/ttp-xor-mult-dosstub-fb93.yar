rule TTP_XOR_MULT_DOSStub_fb93 {
  strings:
    $key_fb93 = { af fb [2] db e3 [2] 9c e1 [2] db f0 [2] 95 fc [2] 99 f6 [2] 8e fd [2] 95 b3 [2] a8 }

  condition:
    any of them
}