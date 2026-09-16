rule TTP_XOR_MULT_DOSStub_669d {
  strings:
    $key_669d = { 32 f5 [2] 46 ed [2] 01 ef [2] 46 fe [2] 08 f2 [2] 04 f8 [2] 13 f3 [2] 08 bd [2] 35 }

  condition:
    any of them
}