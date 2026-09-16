rule TTP_XOR_MULT_DOSStub_dd1b {
  strings:
    $key_dd1b = { 89 73 [2] fd 6b [2] ba 69 [2] fd 78 [2] b3 74 [2] bf 7e [2] a8 75 [2] b3 3b [2] 8e }

  condition:
    any of them
}