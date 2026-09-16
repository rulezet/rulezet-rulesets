rule TTP_XOR_MULT_DOSStub_250f {
  strings:
    $key_250f = { 71 67 [2] 05 7f [2] 42 7d [2] 05 6c [2] 4b 60 [2] 47 6a [2] 50 61 [2] 4b 2f [2] 76 }

  condition:
    any of them
}