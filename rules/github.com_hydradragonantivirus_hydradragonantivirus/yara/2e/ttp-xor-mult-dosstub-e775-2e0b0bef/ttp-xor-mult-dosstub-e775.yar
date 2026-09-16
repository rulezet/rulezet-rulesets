rule TTP_XOR_MULT_DOSStub_e775 {
  strings:
    $key_e775 = { b3 1d [2] c7 05 [2] 80 07 [2] c7 16 [2] 89 1a [2] 85 10 [2] 92 1b [2] 89 55 [2] b4 }

  condition:
    any of them
}