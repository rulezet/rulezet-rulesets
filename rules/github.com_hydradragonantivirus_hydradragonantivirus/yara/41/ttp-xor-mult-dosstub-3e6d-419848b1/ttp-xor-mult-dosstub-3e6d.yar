rule TTP_XOR_MULT_DOSStub_3e6d {
  strings:
    $key_3e6d = { 6a 05 [2] 1e 1d [2] 59 1f [2] 1e 0e [2] 50 02 [2] 5c 08 [2] 4b 03 [2] 50 4d [2] 6d }

  condition:
    any of them
}