rule TTP_XOR_MULT_DOSStub_860f {
  strings:
    $key_860f = { d2 67 [2] a6 7f [2] e1 7d [2] a6 6c [2] e8 60 [2] e4 6a [2] f3 61 [2] e8 2f [2] d5 }

  condition:
    any of them
}