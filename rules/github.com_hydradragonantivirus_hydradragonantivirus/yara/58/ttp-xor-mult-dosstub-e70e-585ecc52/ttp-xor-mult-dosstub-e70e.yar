rule TTP_XOR_MULT_DOSStub_e70e {
  strings:
    $key_e70e = { b3 66 [2] c7 7e [2] 80 7c [2] c7 6d [2] 89 61 [2] 85 6b [2] 92 60 [2] 89 2e [2] b4 }

  condition:
    any of them
}