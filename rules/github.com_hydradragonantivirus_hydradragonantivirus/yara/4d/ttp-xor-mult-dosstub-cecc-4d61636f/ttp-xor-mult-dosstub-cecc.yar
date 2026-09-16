rule TTP_XOR_MULT_DOSStub_cecc {
  strings:
    $key_cecc = { 9a a4 [2] ee bc [2] a9 be [2] ee af [2] a0 a3 [2] ac a9 [2] bb a2 [2] a0 ec [2] 9d }

  condition:
    any of them
}