rule TTP_XOR_MULT_DOSStub_bedc {
  strings:
    $key_bedc = { ea b4 [2] 9e ac [2] d9 ae [2] 9e bf [2] d0 b3 [2] dc b9 [2] cb b2 [2] d0 fc [2] ed }

  condition:
    any of them
}