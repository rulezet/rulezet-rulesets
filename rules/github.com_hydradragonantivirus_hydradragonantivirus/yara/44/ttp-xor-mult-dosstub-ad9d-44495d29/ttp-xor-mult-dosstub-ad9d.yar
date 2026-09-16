rule TTP_XOR_MULT_DOSStub_ad9d {
  strings:
    $key_ad9d = { f9 f5 [2] 8d ed [2] ca ef [2] 8d fe [2] c3 f2 [2] cf f8 [2] d8 f3 [2] c3 bd [2] fe }

  condition:
    any of them
}