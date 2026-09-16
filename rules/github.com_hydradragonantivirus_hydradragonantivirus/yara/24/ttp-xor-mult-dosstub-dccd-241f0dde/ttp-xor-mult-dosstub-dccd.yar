rule TTP_XOR_MULT_DOSStub_dccd {
  strings:
    $key_dccd = { 88 a5 [2] fc bd [2] bb bf [2] fc ae [2] b2 a2 [2] be a8 [2] a9 a3 [2] b2 ed [2] 8f }

  condition:
    any of them
}