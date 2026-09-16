rule TTP_XOR_MULT_DOSStub_d059 {
  strings:
    $key_d059 = { 84 31 [2] f0 29 [2] b7 2b [2] f0 3a [2] be 36 [2] b2 3c [2] a5 37 [2] be 79 [2] 83 }

  condition:
    any of them
}