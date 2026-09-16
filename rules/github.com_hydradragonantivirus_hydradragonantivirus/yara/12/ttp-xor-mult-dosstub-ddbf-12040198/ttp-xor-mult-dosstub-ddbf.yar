rule TTP_XOR_MULT_DOSStub_ddbf {
  strings:
    $key_ddbf = { 89 d7 [2] fd cf [2] ba cd [2] fd dc [2] b3 d0 [2] bf da [2] a8 d1 [2] b3 9f [2] 8e }

  condition:
    any of them
}