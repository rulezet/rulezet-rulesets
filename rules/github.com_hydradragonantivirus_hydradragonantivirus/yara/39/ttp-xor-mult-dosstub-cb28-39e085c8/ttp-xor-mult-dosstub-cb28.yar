rule TTP_XOR_MULT_DOSStub_cb28 {
  strings:
    $key_cb28 = { 9f 40 [2] eb 58 [2] ac 5a [2] eb 4b [2] a5 47 [2] a9 4d [2] be 46 [2] a5 08 [2] 98 }

  condition:
    any of them
}