rule TTP_XOR_MULT_DOSStub_5e1f {
  strings:
    $key_5e1f = { 0a 77 [2] 7e 6f [2] 39 6d [2] 7e 7c [2] 30 70 [2] 3c 7a [2] 2b 71 [2] 30 3f [2] 0d }

  condition:
    any of them
}