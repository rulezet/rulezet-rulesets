rule TTP_XOR_MULT_DOSStub_cb09 {
  strings:
    $key_cb09 = { 9f 61 [2] eb 79 [2] ac 7b [2] eb 6a [2] a5 66 [2] a9 6c [2] be 67 [2] a5 29 [2] 98 }

  condition:
    any of them
}