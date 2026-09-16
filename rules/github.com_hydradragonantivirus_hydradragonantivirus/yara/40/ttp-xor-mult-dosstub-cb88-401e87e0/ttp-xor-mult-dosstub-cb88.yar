rule TTP_XOR_MULT_DOSStub_cb88 {
  strings:
    $key_cb88 = { 9f e0 [2] eb f8 [2] ac fa [2] eb eb [2] a5 e7 [2] a9 ed [2] be e6 [2] a5 a8 [2] 98 }

  condition:
    any of them
}