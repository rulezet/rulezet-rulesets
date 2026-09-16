rule TTP_XOR_MULT_DOSStub_dd0a {
  strings:
    $key_dd0a = { 89 62 [2] fd 7a [2] ba 78 [2] fd 69 [2] b3 65 [2] bf 6f [2] a8 64 [2] b3 2a [2] 8e }

  condition:
    any of them
}