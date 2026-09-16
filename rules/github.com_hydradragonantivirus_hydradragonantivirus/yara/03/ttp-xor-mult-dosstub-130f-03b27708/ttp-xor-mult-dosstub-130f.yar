rule TTP_XOR_MULT_DOSStub_130f {
  strings:
    $key_130f = { 47 67 [2] 33 7f [2] 74 7d [2] 33 6c [2] 7d 60 [2] 71 6a [2] 66 61 [2] 7d 2f [2] 40 }

  condition:
    any of them
}