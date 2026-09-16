rule TTP_XOR_MULT_DOSStub_ff85 {
  strings:
    $key_ff85 = { ab ed [2] df f5 [2] 98 f7 [2] df e6 [2] 91 ea [2] 9d e0 [2] 8a eb [2] 91 a5 [2] ac }

  condition:
    any of them
}