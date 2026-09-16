rule TTP_XOR_MULT_DOSStub_832f {
  strings:
    $key_832f = { d7 47 [2] a3 5f [2] e4 5d [2] a3 4c [2] ed 40 [2] e1 4a [2] f6 41 [2] ed 0f [2] d0 }

  condition:
    any of them
}