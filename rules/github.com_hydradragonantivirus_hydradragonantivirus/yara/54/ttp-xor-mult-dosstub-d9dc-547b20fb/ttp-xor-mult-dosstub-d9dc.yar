rule TTP_XOR_MULT_DOSStub_d9dc {
  strings:
    $key_d9dc = { 8d b4 [2] f9 ac [2] be ae [2] f9 bf [2] b7 b3 [2] bb b9 [2] ac b2 [2] b7 fc [2] 8a }

  condition:
    any of them
}