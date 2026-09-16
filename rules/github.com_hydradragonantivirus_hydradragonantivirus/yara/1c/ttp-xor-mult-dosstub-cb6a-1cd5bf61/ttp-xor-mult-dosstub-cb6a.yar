rule TTP_XOR_MULT_DOSStub_cb6a {
  strings:
    $key_cb6a = { 9f 02 [2] eb 1a [2] ac 18 [2] eb 09 [2] a5 05 [2] a9 0f [2] be 04 [2] a5 4a [2] 98 }

  condition:
    any of them
}