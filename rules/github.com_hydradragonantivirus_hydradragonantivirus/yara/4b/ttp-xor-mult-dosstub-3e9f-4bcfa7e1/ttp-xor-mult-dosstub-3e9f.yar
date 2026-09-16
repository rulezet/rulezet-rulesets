rule TTP_XOR_MULT_DOSStub_3e9f {
  strings:
    $key_3e9f = { 6a f7 [2] 1e ef [2] 59 ed [2] 1e fc [2] 50 f0 [2] 5c fa [2] 4b f1 [2] 50 bf [2] 6d }

  condition:
    any of them
}