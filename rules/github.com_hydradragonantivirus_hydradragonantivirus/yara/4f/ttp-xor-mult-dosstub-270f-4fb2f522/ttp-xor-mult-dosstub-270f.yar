rule TTP_XOR_MULT_DOSStub_270f {
  strings:
    $key_270f = { 73 67 [2] 07 7f [2] 40 7d [2] 07 6c [2] 49 60 [2] 45 6a [2] 52 61 [2] 49 2f [2] 74 }

  condition:
    any of them
}