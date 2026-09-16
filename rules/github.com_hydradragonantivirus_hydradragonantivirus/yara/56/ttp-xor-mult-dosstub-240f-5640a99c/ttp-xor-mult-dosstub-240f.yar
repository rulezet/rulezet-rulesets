rule TTP_XOR_MULT_DOSStub_240f {
  strings:
    $key_240f = { 70 67 [2] 04 7f [2] 43 7d [2] 04 6c [2] 4a 60 [2] 46 6a [2] 51 61 [2] 4a 2f [2] 77 }

  condition:
    any of them
}