rule TTP_XOR_MULT_DOSStub_3edc {
  strings:
    $key_3edc = { 6a b4 [2] 1e ac [2] 59 ae [2] 1e bf [2] 50 b3 [2] 5c b9 [2] 4b b2 [2] 50 fc [2] 6d }

  condition:
    any of them
}