rule TTP_XOR_MULT_DOSStub_e429 {
  strings:
    $key_e429 = { b0 41 [2] c4 59 [2] 83 5b [2] c4 4a [2] 8a 46 [2] 86 4c [2] 91 47 [2] 8a 09 [2] b7 }

  condition:
    any of them
}