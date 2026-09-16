rule TTP_XOR_MULT_DOSStub_bfcf {
  strings:
    $key_bfcf = { eb a7 [2] 9f bf [2] d8 bd [2] 9f ac [2] d1 a0 [2] dd aa [2] ca a1 [2] d1 ef [2] ec }

  condition:
    any of them
}