rule TTP_XOR_MULT_DOSStub_c54d {
  strings:
    $key_c54d = { 91 25 [2] e5 3d [2] a2 3f [2] e5 2e [2] ab 22 [2] a7 28 [2] b0 23 [2] ab 6d [2] 96 }

  condition:
    any of them
}