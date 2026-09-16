rule TTP_XOR_MULT_DOSStub_eed8 {
  strings:
    $key_eed8 = { ba b0 [2] ce a8 [2] 89 aa [2] ce bb [2] 80 b7 [2] 8c bd [2] 9b b6 [2] 80 f8 [2] bd }

  condition:
    any of them
}