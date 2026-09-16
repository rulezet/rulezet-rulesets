rule TTP_XOR_MULT_DOSStub_7dbf {
  strings:
    $key_7dbf = { 29 d7 [2] 5d cf [2] 1a cd [2] 5d dc [2] 13 d0 [2] 1f da [2] 08 d1 [2] 13 9f [2] 2e }

  condition:
    any of them
}