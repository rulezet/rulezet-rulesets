rule TTP_XOR_MULT_DOSStub_decd {
  strings:
    $key_decd = { 8a a5 [2] fe bd [2] b9 bf [2] fe ae [2] b0 a2 [2] bc a8 [2] ab a3 [2] b0 ed [2] 8d }

  condition:
    any of them
}