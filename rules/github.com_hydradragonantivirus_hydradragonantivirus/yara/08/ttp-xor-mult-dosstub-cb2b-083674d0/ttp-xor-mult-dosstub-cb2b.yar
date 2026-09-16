rule TTP_XOR_MULT_DOSStub_cb2b {
  strings:
    $key_cb2b = { 9f 43 [2] eb 5b [2] ac 59 [2] eb 48 [2] a5 44 [2] a9 4e [2] be 45 [2] a5 0b [2] 98 }

  condition:
    any of them
}