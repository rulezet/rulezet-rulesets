rule TTP_XOR_MULT_DOSStub_cb02 {
  strings:
    $key_cb02 = { 9f 6a [2] eb 72 [2] ac 70 [2] eb 61 [2] a5 6d [2] a9 67 [2] be 6c [2] a5 22 [2] 98 }

  condition:
    any of them
}