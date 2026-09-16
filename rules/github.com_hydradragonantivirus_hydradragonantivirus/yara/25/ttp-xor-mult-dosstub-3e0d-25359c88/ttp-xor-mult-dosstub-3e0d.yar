rule TTP_XOR_MULT_DOSStub_3e0d {
  strings:
    $key_3e0d = { 6a 65 [2] 1e 7d [2] 59 7f [2] 1e 6e [2] 50 62 [2] 5c 68 [2] 4b 63 [2] 50 2d [2] 6d }

  condition:
    any of them
}