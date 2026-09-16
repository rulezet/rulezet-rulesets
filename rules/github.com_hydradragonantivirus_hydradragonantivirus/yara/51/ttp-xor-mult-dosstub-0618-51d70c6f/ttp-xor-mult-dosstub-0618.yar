rule TTP_XOR_MULT_DOSStub_0618 {
  strings:
    $key_0618 = { 52 70 [2] 26 68 [2] 61 6a [2] 26 7b [2] 68 77 [2] 64 7d [2] 73 76 [2] 68 38 [2] 55 }

  condition:
    any of them
}