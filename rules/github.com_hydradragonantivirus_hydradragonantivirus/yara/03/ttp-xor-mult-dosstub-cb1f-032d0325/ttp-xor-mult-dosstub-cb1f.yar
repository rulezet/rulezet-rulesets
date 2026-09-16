rule TTP_XOR_MULT_DOSStub_cb1f {
  strings:
    $key_cb1f = { 9f 77 [2] eb 6f [2] ac 6d [2] eb 7c [2] a5 70 [2] a9 7a [2] be 71 [2] a5 3f [2] 98 }

  condition:
    any of them
}