rule TTP_XOR_MULT_DOSStub_dd2e {
  strings:
    $key_dd2e = { 89 46 [2] fd 5e [2] ba 5c [2] fd 4d [2] b3 41 [2] bf 4b [2] a8 40 [2] b3 0e [2] 8e }

  condition:
    any of them
}