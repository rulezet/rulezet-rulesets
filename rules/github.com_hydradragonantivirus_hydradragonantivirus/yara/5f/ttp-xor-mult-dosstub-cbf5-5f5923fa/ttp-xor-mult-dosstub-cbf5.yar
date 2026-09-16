rule TTP_XOR_MULT_DOSStub_cbf5 {
  strings:
    $key_cbf5 = { 9f 9d [2] eb 85 [2] ac 87 [2] eb 96 [2] a5 9a [2] a9 90 [2] be 9b [2] a5 d5 [2] 98 }

  condition:
    any of them
}