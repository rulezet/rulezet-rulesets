rule TTP_XOR_MULT_DOSStub_795d {
  strings:
    $key_795d = { 2d 35 [2] 59 2d [2] 1e 2f [2] 59 3e [2] 17 32 [2] 1b 38 [2] 0c 33 [2] 17 7d [2] 2a }

  condition:
    any of them
}