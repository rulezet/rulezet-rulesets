rule TTP_XOR_MULT_DOSStub_b10f {
  strings:
    $key_b10f = { e5 67 [2] 91 7f [2] d6 7d [2] 91 6c [2] df 60 [2] d3 6a [2] c4 61 [2] df 2f [2] e2 }

  condition:
    any of them
}