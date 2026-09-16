rule TTP_XOR_MULT_DOSStub_2dbf {
  strings:
    $key_2dbf = { 79 d7 [2] 0d cf [2] 4a cd [2] 0d dc [2] 43 d0 [2] 4f da [2] 58 d1 [2] 43 9f [2] 7e }

  condition:
    any of them
}