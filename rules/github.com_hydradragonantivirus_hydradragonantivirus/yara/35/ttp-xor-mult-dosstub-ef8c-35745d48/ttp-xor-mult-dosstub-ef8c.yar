rule TTP_XOR_MULT_DOSStub_ef8c {
  strings:
    $key_ef8c = { bb e4 [2] cf fc [2] 88 fe [2] cf ef [2] 81 e3 [2] 8d e9 [2] 9a e2 [2] 81 ac [2] bc }

  condition:
    any of them
}