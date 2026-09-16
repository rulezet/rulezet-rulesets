rule TTP_XOR_MULT_DOSStub_d76f {
  strings:
    $key_d76f = { 83 07 [2] f7 1f [2] b0 1d [2] f7 0c [2] b9 00 [2] b5 0a [2] a2 01 [2] b9 4f [2] 84 }

  condition:
    any of them
}