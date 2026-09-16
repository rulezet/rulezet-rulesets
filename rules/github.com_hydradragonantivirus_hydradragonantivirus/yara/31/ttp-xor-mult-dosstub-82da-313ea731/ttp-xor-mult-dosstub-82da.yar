rule TTP_XOR_MULT_DOSStub_82da {
  strings:
    $key_82da = { d6 b2 [2] a2 aa [2] e5 a8 [2] a2 b9 [2] ec b5 [2] e0 bf [2] f7 b4 [2] ec fa [2] d1 }

  condition:
    any of them
}