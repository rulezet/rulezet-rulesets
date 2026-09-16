rule TTP_XOR_MULT_DOSStub_e128 {
  strings:
    $key_e128 = { b5 40 [2] c1 58 [2] 86 5a [2] c1 4b [2] 8f 47 [2] 83 4d [2] 94 46 [2] 8f 08 [2] b2 }

  condition:
    any of them
}