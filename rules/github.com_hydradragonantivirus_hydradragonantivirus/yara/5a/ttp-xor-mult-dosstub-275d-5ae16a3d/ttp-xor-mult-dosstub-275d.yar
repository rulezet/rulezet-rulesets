rule TTP_XOR_MULT_DOSStub_275d {
  strings:
    $key_275d = { 73 35 [2] 07 2d [2] 40 2f [2] 07 3e [2] 49 32 [2] 45 38 [2] 52 33 [2] 49 7d [2] 74 }

  condition:
    any of them
}