rule TTP_XOR_MULT_DOSStub_e43c {
  strings:
    $key_e43c = { b0 54 [2] c4 4c [2] 83 4e [2] c4 5f [2] 8a 53 [2] 86 59 [2] 91 52 [2] 8a 1c [2] b7 }

  condition:
    any of them
}