rule TTP_XOR_MULT_DOSStub_760f {
  strings:
    $key_760f = { 22 67 [2] 56 7f [2] 11 7d [2] 56 6c [2] 18 60 [2] 14 6a [2] 03 61 [2] 18 2f [2] 25 }

  condition:
    any of them
}