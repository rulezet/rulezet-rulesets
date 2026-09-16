rule TTP_XOR_MULT_DOSStub_6ada {
  strings:
    $key_6ada = { 3e b2 [2] 4a aa [2] 0d a8 [2] 4a b9 [2] 04 b5 [2] 08 bf [2] 1f b4 [2] 04 fa [2] 39 }

  condition:
    any of them
}