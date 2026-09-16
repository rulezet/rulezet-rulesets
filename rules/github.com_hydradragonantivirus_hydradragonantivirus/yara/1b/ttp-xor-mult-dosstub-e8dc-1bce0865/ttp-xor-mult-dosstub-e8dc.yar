rule TTP_XOR_MULT_DOSStub_e8dc {
  strings:
    $key_e8dc = { bc b4 [2] c8 ac [2] 8f ae [2] c8 bf [2] 86 b3 [2] 8a b9 [2] 9d b2 [2] 86 fc [2] bb }

  condition:
    any of them
}