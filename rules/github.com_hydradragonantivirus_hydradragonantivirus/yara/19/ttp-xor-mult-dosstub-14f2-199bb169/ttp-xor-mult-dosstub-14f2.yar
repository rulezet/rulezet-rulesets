rule TTP_XOR_MULT_DOSStub_14f2 {
  strings:
    $key_14f2 = { 40 9a [2] 34 82 [2] 73 80 [2] 34 91 [2] 7a 9d [2] 76 97 [2] 61 9c [2] 7a d2 [2] 47 }

  condition:
    any of them
}