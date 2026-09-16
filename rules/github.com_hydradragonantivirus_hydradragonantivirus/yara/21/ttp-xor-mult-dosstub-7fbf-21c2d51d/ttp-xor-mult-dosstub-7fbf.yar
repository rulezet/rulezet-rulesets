rule TTP_XOR_MULT_DOSStub_7fbf {
  strings:
    $key_7fbf = { 2b d7 [2] 5f cf [2] 18 cd [2] 5f dc [2] 11 d0 [2] 1d da [2] 0a d1 [2] 11 9f [2] 2c }

  condition:
    any of them
}