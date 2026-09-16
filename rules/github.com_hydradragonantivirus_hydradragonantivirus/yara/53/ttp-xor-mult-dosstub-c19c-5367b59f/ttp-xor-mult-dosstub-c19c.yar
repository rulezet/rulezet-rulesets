rule TTP_XOR_MULT_DOSStub_c19c {
  strings:
    $key_c19c = { 95 f4 [2] e1 ec [2] a6 ee [2] e1 ff [2] af f3 [2] a3 f9 [2] b4 f2 [2] af bc [2] 92 }

  condition:
    any of them
}