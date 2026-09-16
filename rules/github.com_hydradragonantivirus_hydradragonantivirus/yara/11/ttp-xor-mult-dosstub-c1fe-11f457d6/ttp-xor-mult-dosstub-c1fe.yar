rule TTP_XOR_MULT_DOSStub_c1fe {
  strings:
    $key_c1fe = { 95 96 [2] e1 8e [2] a6 8c [2] e1 9d [2] af 91 [2] a3 9b [2] b4 90 [2] af de [2] 92 }

  condition:
    any of them
}