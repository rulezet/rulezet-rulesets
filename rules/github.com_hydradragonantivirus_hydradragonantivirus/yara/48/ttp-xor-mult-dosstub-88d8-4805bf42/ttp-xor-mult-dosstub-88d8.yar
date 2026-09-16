rule TTP_XOR_MULT_DOSStub_88d8 {
  strings:
    $key_88d8 = { dc b0 [2] a8 a8 [2] ef aa [2] a8 bb [2] e6 b7 [2] ea bd [2] fd b6 [2] e6 f8 [2] db }

  condition:
    any of them
}