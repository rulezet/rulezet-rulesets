rule TTP_XOR_MULT_DOSStub_381f {
  strings:
    $key_381f = { 6c 77 [2] 18 6f [2] 5f 6d [2] 18 7c [2] 56 70 [2] 5a 7a [2] 4d 71 [2] 56 3f [2] 6b }

  condition:
    any of them
}