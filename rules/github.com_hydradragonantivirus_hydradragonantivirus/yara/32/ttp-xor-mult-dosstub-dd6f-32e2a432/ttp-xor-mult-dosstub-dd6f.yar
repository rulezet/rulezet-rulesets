rule TTP_XOR_MULT_DOSStub_dd6f {
  strings:
    $key_dd6f = { 89 07 [2] fd 1f [2] ba 1d [2] fd 0c [2] b3 00 [2] bf 0a [2] a8 01 [2] b3 4f [2] 8e }

  condition:
    any of them
}