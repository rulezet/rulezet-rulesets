rule TTP_XOR_MULT_DOSStub_131f {
  strings:
    $key_131f = { 47 77 [2] 33 6f [2] 74 6d [2] 33 7c [2] 7d 70 [2] 71 7a [2] 66 71 [2] 7d 3f [2] 40 }

  condition:
    any of them
}