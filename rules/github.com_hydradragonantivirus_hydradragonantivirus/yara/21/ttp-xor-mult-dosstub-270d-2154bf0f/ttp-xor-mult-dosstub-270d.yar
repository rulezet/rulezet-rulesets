rule TTP_XOR_MULT_DOSStub_270d {
  strings:
    $key_270d = { 73 65 [2] 07 7d [2] 40 7f [2] 07 6e [2] 49 62 [2] 45 68 [2] 52 63 [2] 49 2d [2] 74 }

  condition:
    any of them
}