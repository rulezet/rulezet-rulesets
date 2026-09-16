rule TTP_XOR_MULT_DOSStub_c26f {
  strings:
    $key_c26f = { 96 07 [2] e2 1f [2] a5 1d [2] e2 0c [2] ac 00 [2] a0 0a [2] b7 01 [2] ac 4f [2] 91 }

  condition:
    any of them
}