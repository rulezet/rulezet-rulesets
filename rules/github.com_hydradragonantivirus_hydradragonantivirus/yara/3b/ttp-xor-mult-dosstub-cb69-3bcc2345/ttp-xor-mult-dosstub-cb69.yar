rule TTP_XOR_MULT_DOSStub_cb69 {
  strings:
    $key_cb69 = { 9f 01 [2] eb 19 [2] ac 1b [2] eb 0a [2] a5 06 [2] a9 0c [2] be 07 [2] a5 49 [2] 98 }

  condition:
    any of them
}