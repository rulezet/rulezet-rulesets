rule TTP_XOR_MULT_DOSStub_161f {
  strings:
    $key_161f = { 42 77 [2] 36 6f [2] 71 6d [2] 36 7c [2] 78 70 [2] 74 7a [2] 63 71 [2] 78 3f [2] 45 }

  condition:
    any of them
}