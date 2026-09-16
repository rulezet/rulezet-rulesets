rule TTP_XOR_MULT_DOSStub_28cc {
  strings:
    $key_28cc = { 7c a4 [2] 08 bc [2] 4f be [2] 08 af [2] 46 a3 [2] 4a a9 [2] 5d a2 [2] 46 ec [2] 7b }

  condition:
    any of them
}