rule TTP_XOR_MULT_DOSStub_cbe1 {
  strings:
    $key_cbe1 = { 9f 89 [2] eb 91 [2] ac 93 [2] eb 82 [2] a5 8e [2] a9 84 [2] be 8f [2] a5 c1 [2] 98 }

  condition:
    any of them
}