rule TTP_XOR_MULT_DOSStub_29cc {
  strings:
    $key_29cc = { 7d a4 [2] 09 bc [2] 4e be [2] 09 af [2] 47 a3 [2] 4b a9 [2] 5c a2 [2] 47 ec [2] 7a }

  condition:
    any of them
}