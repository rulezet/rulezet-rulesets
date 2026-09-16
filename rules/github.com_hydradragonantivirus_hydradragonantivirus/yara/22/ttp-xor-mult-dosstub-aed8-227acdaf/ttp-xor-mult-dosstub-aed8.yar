rule TTP_XOR_MULT_DOSStub_aed8 {
  strings:
    $key_aed8 = { fa b0 [2] 8e a8 [2] c9 aa [2] 8e bb [2] c0 b7 [2] cc bd [2] db b6 [2] c0 f8 [2] fd }

  condition:
    any of them
}