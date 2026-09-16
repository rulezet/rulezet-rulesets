rule TTP_XOR_MULT_DOSStub_2e9f {
  strings:
    $key_2e9f = { 7a f7 [2] 0e ef [2] 49 ed [2] 0e fc [2] 40 f0 [2] 4c fa [2] 5b f1 [2] 40 bf [2] 7d }

  condition:
    any of them
}