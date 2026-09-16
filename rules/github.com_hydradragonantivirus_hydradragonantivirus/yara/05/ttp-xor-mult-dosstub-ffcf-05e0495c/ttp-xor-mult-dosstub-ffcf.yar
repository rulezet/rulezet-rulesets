rule TTP_XOR_MULT_DOSStub_ffcf {
  strings:
    $key_ffcf = { ab a7 [2] df bf [2] 98 bd [2] df ac [2] 91 a0 [2] 9d aa [2] 8a a1 [2] 91 ef [2] ac }

  condition:
    any of them
}