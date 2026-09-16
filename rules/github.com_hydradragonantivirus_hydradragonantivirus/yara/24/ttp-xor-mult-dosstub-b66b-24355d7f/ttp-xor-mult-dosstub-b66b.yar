rule TTP_XOR_MULT_DOSStub_b66b {
  strings:
    $key_b66b = { e2 03 [2] 96 1b [2] d1 19 [2] 96 08 [2] d8 04 [2] d4 0e [2] c3 05 [2] d8 4b [2] e5 }

  condition:
    any of them
}