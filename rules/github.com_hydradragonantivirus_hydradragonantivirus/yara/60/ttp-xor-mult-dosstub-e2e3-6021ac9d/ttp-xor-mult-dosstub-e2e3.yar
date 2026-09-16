rule TTP_XOR_MULT_DOSStub_e2e3 {
  strings:
    $key_e2e3 = { b6 8b [2] c2 93 [2] 85 91 [2] c2 80 [2] 8c 8c [2] 80 86 [2] 97 8d [2] 8c c3 [2] b1 }

  condition:
    any of them
}