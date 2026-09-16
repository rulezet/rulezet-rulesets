rule TTP_XOR_MULT_DOSStub_0382 {
  strings:
    $key_0382 = { 57 ea [2] 23 f2 [2] 64 f0 [2] 23 e1 [2] 6d ed [2] 61 e7 [2] 76 ec [2] 6d a2 [2] 50 }

  condition:
    any of them
}