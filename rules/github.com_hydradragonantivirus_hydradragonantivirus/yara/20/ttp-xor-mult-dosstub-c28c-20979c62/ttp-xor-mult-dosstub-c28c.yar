rule TTP_XOR_MULT_DOSStub_c28c {
  strings:
    $key_c28c = { 96 e4 [2] e2 fc [2] a5 fe [2] e2 ef [2] ac e3 [2] a0 e9 [2] b7 e2 [2] ac ac [2] 91 }

  condition:
    any of them
}