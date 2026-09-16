rule TTP_XOR_MULT_DOSStub_d76a {
  strings:
    $key_d76a = { 83 02 [2] f7 1a [2] b0 18 [2] f7 09 [2] b9 05 [2] b5 0f [2] a2 04 [2] b9 4a [2] 84 }

  condition:
    any of them
}