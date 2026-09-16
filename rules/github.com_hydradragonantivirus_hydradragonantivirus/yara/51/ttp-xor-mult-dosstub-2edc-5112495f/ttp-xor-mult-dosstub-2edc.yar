rule TTP_XOR_MULT_DOSStub_2edc {
  strings:
    $key_2edc = { 7a b4 [2] 0e ac [2] 49 ae [2] 0e bf [2] 40 b3 [2] 4c b9 [2] 5b b2 [2] 40 fc [2] 7d }

  condition:
    any of them
}