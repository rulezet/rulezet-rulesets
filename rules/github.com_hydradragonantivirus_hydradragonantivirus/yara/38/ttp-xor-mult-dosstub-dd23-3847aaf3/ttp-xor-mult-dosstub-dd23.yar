rule TTP_XOR_MULT_DOSStub_dd23 {
  strings:
    $key_dd23 = { 89 4b [2] fd 53 [2] ba 51 [2] fd 40 [2] b3 4c [2] bf 46 [2] a8 4d [2] b3 03 [2] 8e }

  condition:
    any of them
}