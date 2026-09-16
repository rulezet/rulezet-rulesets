rule TTP_XOR_MULT_DOSStub_c50f {
  strings:
    $key_c50f = { 91 67 [2] e5 7f [2] a2 7d [2] e5 6c [2] ab 60 [2] a7 6a [2] b0 61 [2] ab 2f [2] 96 }

  condition:
    any of them
}