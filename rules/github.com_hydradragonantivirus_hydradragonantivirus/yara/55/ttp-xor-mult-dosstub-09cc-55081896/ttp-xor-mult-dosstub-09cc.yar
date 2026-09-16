rule TTP_XOR_MULT_DOSStub_09cc {
  strings:
    $key_09cc = { 5d a4 [2] 29 bc [2] 6e be [2] 29 af [2] 67 a3 [2] 6b a9 [2] 7c a2 [2] 67 ec [2] 5a }

  condition:
    any of them
}