rule TTP_XOR_MULT_DOSStub_dcae {
  strings:
    $key_dcae = { 88 c6 [2] fc de [2] bb dc [2] fc cd [2] b2 c1 [2] be cb [2] a9 c0 [2] b2 8e [2] 8f }

  condition:
    any of them
}