rule TTP_XOR_MULT_DOSStub_7ed8 {
  strings:
    $key_7ed8 = { 2a b0 [2] 5e a8 [2] 19 aa [2] 5e bb [2] 10 b7 [2] 1c bd [2] 0b b6 [2] 10 f8 [2] 2d }

  condition:
    any of them
}