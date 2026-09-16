rule TTP_XOR_MULT_DOSStub_a8cc {
  strings:
    $key_a8cc = { fc a4 [2] 88 bc [2] cf be [2] 88 af [2] c6 a3 [2] ca a9 [2] dd a2 [2] c6 ec [2] fb }

  condition:
    any of them
}