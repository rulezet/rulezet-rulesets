rule TTP_XOR_MULT_DOSStub_c36b {
  strings:
    $key_c36b = { 97 03 [2] e3 1b [2] a4 19 [2] e3 08 [2] ad 04 [2] a1 0e [2] b6 05 [2] ad 4b [2] 90 }

  condition:
    any of them
}