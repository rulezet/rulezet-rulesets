rule TTP_XOR_MULT_DOSStub_0a2d {
  strings:
    $key_0a2d = { 5e 45 [2] 2a 5d [2] 6d 5f [2] 2a 4e [2] 64 42 [2] 68 48 [2] 7f 43 [2] 64 0d [2] 59 }

  condition:
    any of them
}