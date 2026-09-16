rule TTP_XOR_MULT_DOSStub_6ebf {
  strings:
    $key_6ebf = { 3a d7 [2] 4e cf [2] 09 cd [2] 4e dc [2] 00 d0 [2] 0c da [2] 1b d1 [2] 00 9f [2] 3d }

  condition:
    any of them
}