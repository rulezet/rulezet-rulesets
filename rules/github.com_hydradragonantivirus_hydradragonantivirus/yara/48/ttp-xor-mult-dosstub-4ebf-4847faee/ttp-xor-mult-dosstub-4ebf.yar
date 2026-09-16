rule TTP_XOR_MULT_DOSStub_4ebf {
  strings:
    $key_4ebf = { 1a d7 [2] 6e cf [2] 29 cd [2] 6e dc [2] 20 d0 [2] 2c da [2] 3b d1 [2] 20 9f [2] 1d }

  condition:
    any of them
}