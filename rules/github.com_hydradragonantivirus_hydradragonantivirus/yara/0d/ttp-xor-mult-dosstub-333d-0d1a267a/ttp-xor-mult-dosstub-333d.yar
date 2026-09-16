rule TTP_XOR_MULT_DOSStub_333d {
  strings:
    $key_333d = { 67 55 [2] 13 4d [2] 54 4f [2] 13 5e [2] 5d 52 [2] 51 58 [2] 46 53 [2] 5d 1d [2] 60 }

  condition:
    any of them
}