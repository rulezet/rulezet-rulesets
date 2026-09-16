rule TTP_XOR_MULT_DOSStub_cb91 {
  strings:
    $key_cb91 = { 9f f9 [2] eb e1 [2] ac e3 [2] eb f2 [2] a5 fe [2] a9 f4 [2] be ff [2] a5 b1 [2] 98 }

  condition:
    any of them
}