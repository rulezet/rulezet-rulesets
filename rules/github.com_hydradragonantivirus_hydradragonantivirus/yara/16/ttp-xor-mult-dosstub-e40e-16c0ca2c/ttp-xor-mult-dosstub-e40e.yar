rule TTP_XOR_MULT_DOSStub_e40e {
  strings:
    $key_e40e = { b0 66 [2] c4 7e [2] 83 7c [2] c4 6d [2] 8a 61 [2] 86 6b [2] 91 60 [2] 8a 2e [2] b7 }

  condition:
    any of them
}