rule TTP_XOR_MULT_DOSStub_4e9f {
  strings:
    $key_4e9f = { 1a f7 [2] 6e ef [2] 29 ed [2] 6e fc [2] 20 f0 [2] 2c fa [2] 3b f1 [2] 20 bf [2] 1d }

  condition:
    any of them
}