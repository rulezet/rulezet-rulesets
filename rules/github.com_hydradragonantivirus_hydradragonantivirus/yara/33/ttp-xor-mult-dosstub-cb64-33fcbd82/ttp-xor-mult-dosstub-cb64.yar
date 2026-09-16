rule TTP_XOR_MULT_DOSStub_cb64 {
  strings:
    $key_cb64 = { 9f 0c [2] eb 14 [2] ac 16 [2] eb 07 [2] a5 0b [2] a9 01 [2] be 0a [2] a5 44 [2] 98 }

  condition:
    any of them
}