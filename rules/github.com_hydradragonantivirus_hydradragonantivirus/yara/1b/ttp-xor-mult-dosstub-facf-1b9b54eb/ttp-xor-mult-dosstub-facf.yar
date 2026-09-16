rule TTP_XOR_MULT_DOSStub_facf {
  strings:
    $key_facf = { ae a7 [2] da bf [2] 9d bd [2] da ac [2] 94 a0 [2] 98 aa [2] 8f a1 [2] 94 ef [2] a9 }

  condition:
    any of them
}