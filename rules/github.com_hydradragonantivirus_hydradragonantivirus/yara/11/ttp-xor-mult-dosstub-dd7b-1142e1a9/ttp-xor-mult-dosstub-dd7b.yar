rule TTP_XOR_MULT_DOSStub_dd7b {
  strings:
    $key_dd7b = { 89 13 [2] fd 0b [2] ba 09 [2] fd 18 [2] b3 14 [2] bf 1e [2] a8 15 [2] b3 5b [2] 8e }

  condition:
    any of them
}