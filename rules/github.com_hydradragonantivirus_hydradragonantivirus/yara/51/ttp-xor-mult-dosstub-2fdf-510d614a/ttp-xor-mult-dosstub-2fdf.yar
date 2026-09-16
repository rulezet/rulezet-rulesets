rule TTP_XOR_MULT_DOSStub_2fdf {
  strings:
    $key_2fdf = { 7b b7 [2] 0f af [2] 48 ad [2] 0f bc [2] 41 b0 [2] 4d ba [2] 5a b1 [2] 41 ff [2] 7c }

  condition:
    any of them
}