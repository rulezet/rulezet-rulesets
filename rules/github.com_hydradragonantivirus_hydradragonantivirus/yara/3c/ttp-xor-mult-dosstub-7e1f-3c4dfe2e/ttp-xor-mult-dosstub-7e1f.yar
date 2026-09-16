rule TTP_XOR_MULT_DOSStub_7e1f {
  strings:
    $key_7e1f = { 2a 77 [2] 5e 6f [2] 19 6d [2] 5e 7c [2] 10 70 [2] 1c 7a [2] 0b 71 [2] 10 3f [2] 2d }

  condition:
    any of them
}