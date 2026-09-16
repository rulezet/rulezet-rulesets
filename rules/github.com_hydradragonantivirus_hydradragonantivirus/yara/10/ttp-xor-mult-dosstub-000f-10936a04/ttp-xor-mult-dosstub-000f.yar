rule TTP_XOR_MULT_DOSStub_000f {
  strings:
    $key_000f = { 54 67 [2] 20 7f [2] 67 7d [2] 20 6c [2] 6e 60 [2] 62 6a [2] 75 61 [2] 6e 2f [2] 53 }

  condition:
    any of them
}