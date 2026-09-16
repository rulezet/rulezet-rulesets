rule TTP_XOR_MULT_DOSStub_dd2f {
  strings:
    $key_dd2f = { 89 47 [2] fd 5f [2] ba 5d [2] fd 4c [2] b3 40 [2] bf 4a [2] a8 41 [2] b3 0f [2] 8e }

  condition:
    any of them
}