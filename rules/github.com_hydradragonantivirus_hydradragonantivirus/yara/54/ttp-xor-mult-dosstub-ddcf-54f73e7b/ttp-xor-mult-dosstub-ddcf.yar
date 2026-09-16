rule TTP_XOR_MULT_DOSStub_ddcf {
  strings:
    $key_ddcf = { 89 a7 [2] fd bf [2] ba bd [2] fd ac [2] b3 a0 [2] bf aa [2] a8 a1 [2] b3 ef [2] 8e }

  condition:
    any of them
}