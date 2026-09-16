rule TTP_XOR_MULT_DOSStub_89cc {
  strings:
    $key_89cc = { dd a4 [2] a9 bc [2] ee be [2] a9 af [2] e7 a3 [2] eb a9 [2] fc a2 [2] e7 ec [2] da }

  condition:
    any of them
}