rule TTP_XOR_MULT_DOSStub_0d1f {
  strings:
    $key_0d1f = { 59 77 [2] 2d 6f [2] 6a 6d [2] 2d 7c [2] 63 70 [2] 6f 7a [2] 78 71 [2] 63 3f [2] 5e }

  condition:
    any of them
}