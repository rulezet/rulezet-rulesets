rule TTP_XOR_MULT_DOSStub_111f {
  strings:
    $key_111f = { 45 77 [2] 31 6f [2] 76 6d [2] 31 7c [2] 7f 70 [2] 73 7a [2] 64 71 [2] 7f 3f [2] 42 }

  condition:
    any of them
}