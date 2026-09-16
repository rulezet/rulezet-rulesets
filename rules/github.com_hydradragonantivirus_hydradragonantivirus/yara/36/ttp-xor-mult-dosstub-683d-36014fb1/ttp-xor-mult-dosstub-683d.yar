rule TTP_XOR_MULT_DOSStub_683d {
  strings:
    $key_683d = { 3c 55 [2] 48 4d [2] 0f 4f [2] 48 5e [2] 06 52 [2] 0a 58 [2] 1d 53 [2] 06 1d [2] 3b }

  condition:
    any of them
}