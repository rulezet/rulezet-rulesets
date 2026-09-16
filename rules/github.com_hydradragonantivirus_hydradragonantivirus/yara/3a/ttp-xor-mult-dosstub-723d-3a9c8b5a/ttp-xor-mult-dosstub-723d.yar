rule TTP_XOR_MULT_DOSStub_723d {
  strings:
    $key_723d = { 26 55 [2] 52 4d [2] 15 4f [2] 52 5e [2] 1c 52 [2] 10 58 [2] 07 53 [2] 1c 1d [2] 21 }

  condition:
    any of them
}