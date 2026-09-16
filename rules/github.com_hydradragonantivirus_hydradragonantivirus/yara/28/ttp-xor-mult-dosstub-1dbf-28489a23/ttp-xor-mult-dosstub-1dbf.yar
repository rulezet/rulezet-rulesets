rule TTP_XOR_MULT_DOSStub_1dbf {
  strings:
    $key_1dbf = { 49 d7 [2] 3d cf [2] 7a cd [2] 3d dc [2] 73 d0 [2] 7f da [2] 68 d1 [2] 73 9f [2] 4e }

  condition:
    any of them
}