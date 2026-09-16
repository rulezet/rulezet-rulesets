rule TTP_XOR_MULT_DOSStub_501f {
  strings:
    $key_501f = { 04 77 [2] 70 6f [2] 37 6d [2] 70 7c [2] 3e 70 [2] 32 7a [2] 25 71 [2] 3e 3f [2] 03 }

  condition:
    any of them
}