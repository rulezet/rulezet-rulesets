rule TTP_XOR_MULT_DOSStub_8acf {
  strings:
    $key_8acf = { de a7 [2] aa bf [2] ed bd [2] aa ac [2] e4 a0 [2] e8 aa [2] ff a1 [2] e4 ef [2] d9 }

  condition:
    any of them
}