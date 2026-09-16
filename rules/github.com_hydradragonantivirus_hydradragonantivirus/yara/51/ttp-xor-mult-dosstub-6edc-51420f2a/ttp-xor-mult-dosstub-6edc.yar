rule TTP_XOR_MULT_DOSStub_6edc {
  strings:
    $key_6edc = { 3a b4 [2] 4e ac [2] 09 ae [2] 4e bf [2] 00 b3 [2] 0c b9 [2] 1b b2 [2] 00 fc [2] 3d }

  condition:
    any of them
}