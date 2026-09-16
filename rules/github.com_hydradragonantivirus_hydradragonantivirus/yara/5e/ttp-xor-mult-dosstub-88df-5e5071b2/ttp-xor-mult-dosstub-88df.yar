rule TTP_XOR_MULT_DOSStub_88df {
  strings:
    $key_88df = { dc b7 [2] a8 af [2] ef ad [2] a8 bc [2] e6 b0 [2] ea ba [2] fd b1 [2] e6 ff [2] db }

  condition:
    any of them
}