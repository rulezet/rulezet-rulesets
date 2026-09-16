rule TTP_XOR_MULT_DOSStub_6ed8 {
  strings:
    $key_6ed8 = { 3a b0 [2] 4e a8 [2] 09 aa [2] 4e bb [2] 00 b7 [2] 0c bd [2] 1b b6 [2] 00 f8 [2] 3d }

  condition:
    any of them
}