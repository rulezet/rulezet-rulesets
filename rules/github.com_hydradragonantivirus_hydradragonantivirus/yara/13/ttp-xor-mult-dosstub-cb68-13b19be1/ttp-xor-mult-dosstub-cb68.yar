rule TTP_XOR_MULT_DOSStub_cb68 {
  strings:
    $key_cb68 = { 9f 00 [2] eb 18 [2] ac 1a [2] eb 0b [2] a5 07 [2] a9 0d [2] be 06 [2] a5 48 [2] 98 }

  condition:
    any of them
}