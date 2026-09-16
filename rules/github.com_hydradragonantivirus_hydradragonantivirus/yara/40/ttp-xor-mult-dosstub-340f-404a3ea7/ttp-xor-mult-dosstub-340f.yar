rule TTP_XOR_MULT_DOSStub_340f {
  strings:
    $key_340f = { 60 67 [2] 14 7f [2] 53 7d [2] 14 6c [2] 5a 60 [2] 56 6a [2] 41 61 [2] 5a 2f [2] 67 }

  condition:
    any of them
}