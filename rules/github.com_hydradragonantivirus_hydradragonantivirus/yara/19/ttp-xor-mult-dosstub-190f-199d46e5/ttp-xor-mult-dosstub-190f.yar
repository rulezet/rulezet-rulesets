rule TTP_XOR_MULT_DOSStub_190f {
  strings:
    $key_190f = { 4d 67 [2] 39 7f [2] 7e 7d [2] 39 6c [2] 77 60 [2] 7b 6a [2] 6c 61 [2] 77 2f [2] 4a }

  condition:
    any of them
}