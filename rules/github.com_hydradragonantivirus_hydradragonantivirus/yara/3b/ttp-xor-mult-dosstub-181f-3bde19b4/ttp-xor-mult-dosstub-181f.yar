rule TTP_XOR_MULT_DOSStub_181f {
  strings:
    $key_181f = { 4c 77 [2] 38 6f [2] 7f 6d [2] 38 7c [2] 76 70 [2] 7a 7a [2] 6d 71 [2] 76 3f [2] 4b }

  condition:
    any of them
}