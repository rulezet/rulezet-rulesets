rule TTP_XOR_MULT_DOSStub_936d {
  strings:
    $key_936d = { c7 05 [2] b3 1d [2] f4 1f [2] b3 0e [2] fd 02 [2] f1 08 [2] e6 03 [2] fd 4d [2] c0 }

  condition:
    any of them
}