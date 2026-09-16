rule TTP_XOR_MULT_DOSStub_828f {
  strings:
    $key_828f = { d6 e7 [2] a2 ff [2] e5 fd [2] a2 ec [2] ec e0 [2] e0 ea [2] f7 e1 [2] ec af [2] d1 }

  condition:
    any of them
}