rule TTP_XOR_MULT_DOSStub_82d8 {
  strings:
    $key_82d8 = { d6 b0 [2] a2 a8 [2] e5 aa [2] a2 bb [2] ec b7 [2] e0 bd [2] f7 b6 [2] ec f8 [2] d1 }

  condition:
    any of them
}