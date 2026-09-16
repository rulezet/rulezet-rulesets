rule TTP_XOR_MULT_DOSStub_cdca {
  strings:
    $key_cdca = { 99 a2 [2] ed ba [2] aa b8 [2] ed a9 [2] a3 a5 [2] af af [2] b8 a4 [2] a3 ea [2] 9e }

  condition:
    any of them
}