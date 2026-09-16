rule TTP_XOR_MULT_DOSStub_4618 {
  strings:
    $key_4618 = { 12 70 [2] 66 68 [2] 21 6a [2] 66 7b [2] 28 77 [2] 24 7d [2] 33 76 [2] 28 38 [2] 15 }

  condition:
    any of them
}