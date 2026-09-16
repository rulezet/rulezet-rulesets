rule TTP_XOR_MULT_DOSStub_dd1e {
  strings:
    $key_dd1e = { 89 76 [2] fd 6e [2] ba 6c [2] fd 7d [2] b3 71 [2] bf 7b [2] a8 70 [2] b3 3e [2] 8e }

  condition:
    any of them
}