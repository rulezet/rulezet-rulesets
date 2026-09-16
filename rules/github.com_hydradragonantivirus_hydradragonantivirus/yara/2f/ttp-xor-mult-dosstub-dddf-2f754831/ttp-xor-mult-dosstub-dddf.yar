rule TTP_XOR_MULT_DOSStub_dddf {
  strings:
    $key_dddf = { 89 b7 [2] fd af [2] ba ad [2] fd bc [2] b3 b0 [2] bf ba [2] a8 b1 [2] b3 ff [2] 8e }

  condition:
    any of them
}