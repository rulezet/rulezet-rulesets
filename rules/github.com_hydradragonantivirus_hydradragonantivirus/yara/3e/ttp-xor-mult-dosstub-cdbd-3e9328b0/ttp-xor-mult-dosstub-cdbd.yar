rule TTP_XOR_MULT_DOSStub_cdbd {
  strings:
    $key_cdbd = { 99 d5 [2] ed cd [2] aa cf [2] ed de [2] a3 d2 [2] af d8 [2] b8 d3 [2] a3 9d [2] 9e }

  condition:
    any of them
}