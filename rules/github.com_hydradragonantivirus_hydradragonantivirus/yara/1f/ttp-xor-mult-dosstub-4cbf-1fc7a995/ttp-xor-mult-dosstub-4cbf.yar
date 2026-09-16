rule TTP_XOR_MULT_DOSStub_4cbf {
  strings:
    $key_4cbf = { 18 d7 [2] 6c cf [2] 2b cd [2] 6c dc [2] 22 d0 [2] 2e da [2] 39 d1 [2] 22 9f [2] 1f }

  condition:
    any of them
}