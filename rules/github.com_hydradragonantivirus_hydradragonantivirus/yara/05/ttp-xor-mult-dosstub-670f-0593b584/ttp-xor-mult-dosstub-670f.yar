rule TTP_XOR_MULT_DOSStub_670f {
  strings:
    $key_670f = { 33 67 [2] 47 7f [2] 00 7d [2] 47 6c [2] 09 60 [2] 05 6a [2] 12 61 [2] 09 2f [2] 34 }

  condition:
    any of them
}