rule TTP_XOR_MULT_DOSStub_8b3d {
  strings:
    $key_8b3d = { df 55 [2] ab 4d [2] ec 4f [2] ab 5e [2] e5 52 [2] e9 58 [2] fe 53 [2] e5 1d [2] d8 }

  condition:
    any of them
}