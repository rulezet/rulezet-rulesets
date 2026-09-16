rule TTP_XOR_MULT_DOSStub_360f {
  strings:
    $key_360f = { 62 67 [2] 16 7f [2] 51 7d [2] 16 6c [2] 58 60 [2] 54 6a [2] 43 61 [2] 58 2f [2] 65 }

  condition:
    any of them
}