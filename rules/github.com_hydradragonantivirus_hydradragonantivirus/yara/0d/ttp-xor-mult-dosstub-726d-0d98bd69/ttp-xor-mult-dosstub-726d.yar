rule TTP_XOR_MULT_DOSStub_726d {
  strings:
    $key_726d = { 26 05 [2] 52 1d [2] 15 1f [2] 52 0e [2] 1c 02 [2] 10 08 [2] 07 03 [2] 1c 4d [2] 21 }

  condition:
    any of them
}