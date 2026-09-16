rule TTP_XOR_MULT_DOSStub_8769 {
  strings:
    $key_8769 = { d3 01 [2] a7 19 [2] e0 1b [2] a7 0a [2] e9 06 [2] e5 0c [2] f2 07 [2] e9 49 [2] d4 }

  condition:
    any of them
}