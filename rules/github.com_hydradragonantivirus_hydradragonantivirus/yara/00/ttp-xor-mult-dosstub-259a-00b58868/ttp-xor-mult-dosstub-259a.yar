rule TTP_XOR_MULT_DOSStub_259a {
  strings:
    $key_259a = { 71 f2 [2] 05 ea [2] 42 e8 [2] 05 f9 [2] 4b f5 [2] 47 ff [2] 50 f4 [2] 4b ba [2] 76 }

  condition:
    any of them
}