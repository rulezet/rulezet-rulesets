rule TTP_XOR_MULT_DOSStub_82df {
  strings:
    $key_82df = { d6 b7 [2] a2 af [2] e5 ad [2] a2 bc [2] ec b0 [2] e0 ba [2] f7 b1 [2] ec ff [2] d1 }

  condition:
    any of them
}