rule TTP_XOR_MULT_DOSStub_289d {
  strings:
    $key_289d = { 7c f5 [2] 08 ed [2] 4f ef [2] 08 fe [2] 46 f2 [2] 4a f8 [2] 5d f3 [2] 46 bd [2] 7b }

  condition:
    any of them
}