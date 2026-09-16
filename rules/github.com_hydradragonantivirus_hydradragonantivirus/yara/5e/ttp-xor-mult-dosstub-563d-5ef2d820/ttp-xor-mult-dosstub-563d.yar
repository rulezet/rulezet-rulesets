rule TTP_XOR_MULT_DOSStub_563d {
  strings:
    $key_563d = { 02 55 [2] 76 4d [2] 31 4f [2] 76 5e [2] 38 52 [2] 34 58 [2] 23 53 [2] 38 1d [2] 05 }

  condition:
    any of them
}