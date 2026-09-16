rule TTP_XOR_MULT_DOSStub_c54f {
  strings:
    $key_c54f = { 91 27 [2] e5 3f [2] a2 3d [2] e5 2c [2] ab 20 [2] a7 2a [2] b0 21 [2] ab 6f [2] 96 }

  condition:
    any of them
}