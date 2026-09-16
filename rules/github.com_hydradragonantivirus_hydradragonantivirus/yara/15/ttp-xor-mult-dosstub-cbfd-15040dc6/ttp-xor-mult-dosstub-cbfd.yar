rule TTP_XOR_MULT_DOSStub_cbfd {
  strings:
    $key_cbfd = { 9f 95 [2] eb 8d [2] ac 8f [2] eb 9e [2] a5 92 [2] a9 98 [2] be 93 [2] a5 dd [2] 98 }

  condition:
    any of them
}