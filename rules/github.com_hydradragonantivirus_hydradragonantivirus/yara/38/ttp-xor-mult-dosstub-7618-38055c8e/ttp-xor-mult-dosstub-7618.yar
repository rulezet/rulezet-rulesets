rule TTP_XOR_MULT_DOSStub_7618 {
  strings:
    $key_7618 = { 22 70 [2] 56 68 [2] 11 6a [2] 56 7b [2] 18 77 [2] 14 7d [2] 03 76 [2] 18 38 [2] 25 }

  condition:
    any of them
}