rule TTP_XOR_MULT_DOSStub_510f {
  strings:
    $key_510f = { 05 67 [2] 71 7f [2] 36 7d [2] 71 6c [2] 3f 60 [2] 33 6a [2] 24 61 [2] 3f 2f [2] 02 }

  condition:
    any of them
}