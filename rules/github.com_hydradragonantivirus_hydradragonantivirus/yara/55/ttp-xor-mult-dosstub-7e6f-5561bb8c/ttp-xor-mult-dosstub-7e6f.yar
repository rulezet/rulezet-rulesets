rule TTP_XOR_MULT_DOSStub_7e6f {
  strings:
    $key_7e6f = { 2a 07 [2] 5e 1f [2] 19 1d [2] 5e 0c [2] 10 00 [2] 1c 0a [2] 0b 01 [2] 10 4f [2] 2d }

  condition:
    any of them
}