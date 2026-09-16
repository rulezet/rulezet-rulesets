rule TTP_XOR_MULT_DOSStub_cbee {
  strings:
    $key_cbee = { 9f 86 [2] eb 9e [2] ac 9c [2] eb 8d [2] a5 81 [2] a9 8b [2] be 80 [2] a5 ce [2] 98 }

  condition:
    any of them
}