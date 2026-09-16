rule TTP_XOR_MULT_DOSStub_efdc {
  strings:
    $key_efdc = { bb b4 [2] cf ac [2] 88 ae [2] cf bf [2] 81 b3 [2] 8d b9 [2] 9a b2 [2] 81 fc [2] bc }

  condition:
    any of them
}