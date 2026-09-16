rule TTP_XOR_MULT_DOSStub_dd2b {
  strings:
    $key_dd2b = { 89 43 [2] fd 5b [2] ba 59 [2] fd 48 [2] b3 44 [2] bf 4e [2] a8 45 [2] b3 0b [2] 8e }

  condition:
    any of them
}