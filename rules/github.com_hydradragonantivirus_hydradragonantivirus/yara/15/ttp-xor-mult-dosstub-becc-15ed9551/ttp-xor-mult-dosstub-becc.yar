rule TTP_XOR_MULT_DOSStub_becc {
  strings:
    $key_becc = { ea a4 [2] 9e bc [2] d9 be [2] 9e af [2] d0 a3 [2] dc a9 [2] cb a2 [2] d0 ec [2] ed }

  condition:
    any of them
}