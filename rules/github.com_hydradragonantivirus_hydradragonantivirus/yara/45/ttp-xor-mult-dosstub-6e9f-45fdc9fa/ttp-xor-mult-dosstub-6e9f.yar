rule TTP_XOR_MULT_DOSStub_6e9f {
  strings:
    $key_6e9f = { 3a f7 [2] 4e ef [2] 09 ed [2] 4e fc [2] 00 f0 [2] 0c fa [2] 1b f1 [2] 00 bf [2] 3d }

  condition:
    any of them
}