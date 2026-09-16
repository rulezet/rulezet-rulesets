rule TTP_XOR_MULT_DOSStub_050f {
  strings:
    $key_050f = { 51 67 [2] 25 7f [2] 62 7d [2] 25 6c [2] 6b 60 [2] 67 6a [2] 70 61 [2] 6b 2f [2] 56 }

  condition:
    any of them
}