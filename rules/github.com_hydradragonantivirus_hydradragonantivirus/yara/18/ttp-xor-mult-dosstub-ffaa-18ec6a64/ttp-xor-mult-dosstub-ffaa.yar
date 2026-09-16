rule TTP_XOR_MULT_DOSStub_ffaa {
  strings:
    $key_ffaa = { ab c2 [2] df da [2] 98 d8 [2] df c9 [2] 91 c5 [2] 9d cf [2] 8a c4 [2] 91 8a [2] ac }

  condition:
    any of them
}