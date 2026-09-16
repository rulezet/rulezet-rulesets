rule TTP_XOR_MULT_DOSStub_b26b {
  strings:
    $key_b26b = { e6 03 [2] 92 1b [2] d5 19 [2] 92 08 [2] dc 04 [2] d0 0e [2] c7 05 [2] dc 4b [2] e1 }

  condition:
    any of them
}