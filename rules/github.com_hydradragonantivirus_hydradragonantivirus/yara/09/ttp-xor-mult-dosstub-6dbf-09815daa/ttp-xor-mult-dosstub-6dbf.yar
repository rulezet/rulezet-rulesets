rule TTP_XOR_MULT_DOSStub_6dbf {
  strings:
    $key_6dbf = { 39 d7 [2] 4d cf [2] 0a cd [2] 4d dc [2] 03 d0 [2] 0f da [2] 18 d1 [2] 03 9f [2] 3e }

  condition:
    any of them
}