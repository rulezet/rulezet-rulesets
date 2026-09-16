rule TTP_XOR_MULT_DOSStub_0cbf {
  strings:
    $key_0cbf = { 58 d7 [2] 2c cf [2] 6b cd [2] 2c dc [2] 62 d0 [2] 6e da [2] 79 d1 [2] 62 9f [2] 5f }

  condition:
    any of them
}