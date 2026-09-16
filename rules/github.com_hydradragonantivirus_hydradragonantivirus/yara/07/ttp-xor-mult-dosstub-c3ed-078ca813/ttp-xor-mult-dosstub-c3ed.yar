rule TTP_XOR_MULT_DOSStub_c3ed {
  strings:
    $key_c3ed = { 97 85 [2] e3 9d [2] a4 9f [2] e3 8e [2] ad 82 [2] a1 88 [2] b6 83 [2] ad cd [2] 90 }

  condition:
    any of them
}