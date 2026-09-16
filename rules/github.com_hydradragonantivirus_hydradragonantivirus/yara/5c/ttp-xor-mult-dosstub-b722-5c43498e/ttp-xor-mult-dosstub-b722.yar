rule TTP_XOR_MULT_DOSStub_b722 {
  strings:
    $key_b722 = { e3 4a [2] 97 52 [2] d0 50 [2] 97 41 [2] d9 4d [2] d5 47 [2] c2 4c [2] d9 02 [2] e4 }

  condition:
    any of them
}