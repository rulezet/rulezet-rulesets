rule TTP_XOR_MULT_DOSStub_ffdd {
  strings:
    $key_ffdd = { ab b5 [2] df ad [2] 98 af [2] df be [2] 91 b2 [2] 9d b8 [2] 8a b3 [2] 91 fd [2] ac }

  condition:
    any of them
}