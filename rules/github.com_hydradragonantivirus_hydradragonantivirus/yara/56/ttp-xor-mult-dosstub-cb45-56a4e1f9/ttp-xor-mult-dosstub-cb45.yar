rule TTP_XOR_MULT_DOSStub_cb45 {
  strings:
    $key_cb45 = { 9f 2d [2] eb 35 [2] ac 37 [2] eb 26 [2] a5 2a [2] a9 20 [2] be 2b [2] a5 65 [2] 98 }

  condition:
    any of them
}