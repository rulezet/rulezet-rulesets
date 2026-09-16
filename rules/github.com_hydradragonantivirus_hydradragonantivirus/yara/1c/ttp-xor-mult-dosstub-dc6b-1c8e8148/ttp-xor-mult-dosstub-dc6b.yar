rule TTP_XOR_MULT_DOSStub_dc6b {
  strings:
    $key_dc6b = { 88 03 [2] fc 1b [2] bb 19 [2] fc 08 [2] b2 04 [2] be 0e [2] a9 05 [2] b2 4b [2] 8f }

  condition:
    any of them
}