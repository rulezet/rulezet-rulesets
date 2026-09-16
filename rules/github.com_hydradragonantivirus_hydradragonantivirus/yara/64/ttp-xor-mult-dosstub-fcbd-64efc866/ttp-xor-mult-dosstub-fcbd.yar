rule TTP_XOR_MULT_DOSStub_fcbd {
  strings:
    $key_fcbd = { a8 d5 [2] dc cd [2] 9b cf [2] dc de [2] 92 d2 [2] 9e d8 [2] 89 d3 [2] 92 9d [2] af }

  condition:
    any of them
}