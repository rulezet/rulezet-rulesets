rule TTP_XOR_MULT_DOSStub_c94d {
  strings:
    $key_c94d = { 9d 25 [2] e9 3d [2] ae 3f [2] e9 2e [2] a7 22 [2] ab 28 [2] bc 23 [2] a7 6d [2] 9a }

  condition:
    any of them
}