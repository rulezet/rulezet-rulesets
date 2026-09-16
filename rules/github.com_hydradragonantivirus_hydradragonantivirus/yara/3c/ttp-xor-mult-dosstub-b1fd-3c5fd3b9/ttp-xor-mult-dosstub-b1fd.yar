rule TTP_XOR_MULT_DOSStub_b1fd {
  strings:
    $key_b1fd = { e5 95 [2] 91 8d [2] d6 8f [2] 91 9e [2] df 92 [2] d3 98 [2] c4 93 [2] df dd [2] e2 }

  condition:
    any of them
}