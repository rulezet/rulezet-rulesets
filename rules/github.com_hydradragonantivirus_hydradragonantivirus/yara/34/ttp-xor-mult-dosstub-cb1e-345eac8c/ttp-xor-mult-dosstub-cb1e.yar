rule TTP_XOR_MULT_DOSStub_cb1e {
  strings:
    $key_cb1e = { 9f 76 [2] eb 6e [2] ac 6c [2] eb 7d [2] a5 71 [2] a9 7b [2] be 70 [2] a5 3e [2] 98 }

  condition:
    any of them
}