rule TTP_XOR_MULT_DOSStub_e1fd {
  strings:
    $key_e1fd = { b5 95 [2] c1 8d [2] 86 8f [2] c1 9e [2] 8f 92 [2] 83 98 [2] 94 93 [2] 8f dd [2] b2 }

  condition:
    any of them
}