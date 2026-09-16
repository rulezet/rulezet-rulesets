rule TTP_XOR_MULT_DOSStub_c54e {
  strings:
    $key_c54e = { 91 26 [2] e5 3e [2] a2 3c [2] e5 2d [2] ab 21 [2] a7 2b [2] b0 20 [2] ab 6e [2] 96 }

  condition:
    any of them
}