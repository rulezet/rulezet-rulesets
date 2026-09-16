rule TTP_XOR_MULT_DOSStub_576f {
  strings:
    $key_576f = { 03 07 [2] 77 1f [2] 30 1d [2] 77 0c [2] 39 00 [2] 35 0a [2] 22 01 [2] 39 4f [2] 04 }

  condition:
    any of them
}