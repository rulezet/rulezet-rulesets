rule TTP_XOR_MULT_DOSStub_273d {
  strings:
    $key_273d = { 73 55 [2] 07 4d [2] 40 4f [2] 07 5e [2] 49 52 [2] 45 58 [2] 52 53 [2] 49 1d [2] 74 }

  condition:
    any of them
}