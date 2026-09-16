rule TTP_XOR_MULT_DOSStub_d30f {
  strings:
    $key_d30f = { 87 67 [2] f3 7f [2] b4 7d [2] f3 6c [2] bd 60 [2] b1 6a [2] a6 61 [2] bd 2f [2] 80 }

  condition:
    any of them
}