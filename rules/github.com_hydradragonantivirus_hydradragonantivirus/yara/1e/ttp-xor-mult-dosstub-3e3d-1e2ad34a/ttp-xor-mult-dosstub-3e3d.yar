rule TTP_XOR_MULT_DOSStub_3e3d {
  strings:
    $key_3e3d = { 6a 55 [2] 1e 4d [2] 59 4f [2] 1e 5e [2] 50 52 [2] 5c 58 [2] 4b 53 [2] 50 1d [2] 6d }

  condition:
    any of them
}