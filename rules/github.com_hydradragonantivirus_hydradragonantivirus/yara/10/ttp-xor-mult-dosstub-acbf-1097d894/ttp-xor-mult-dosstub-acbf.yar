rule TTP_XOR_MULT_DOSStub_acbf {
  strings:
    $key_acbf = { f8 d7 [2] 8c cf [2] cb cd [2] 8c dc [2] c2 d0 [2] ce da [2] d9 d1 [2] c2 9f [2] ff }

  condition:
    any of them
}