rule TTP_XOR_MULT_DOSStub_163d {
  strings:
    $key_163d = { 42 55 [2] 36 4d [2] 71 4f [2] 36 5e [2] 78 52 [2] 74 58 [2] 63 53 [2] 78 1d [2] 45 }

  condition:
    any of them
}