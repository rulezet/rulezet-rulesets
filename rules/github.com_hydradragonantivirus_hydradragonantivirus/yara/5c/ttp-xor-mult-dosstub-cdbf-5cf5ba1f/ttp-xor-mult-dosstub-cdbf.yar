rule TTP_XOR_MULT_DOSStub_cdbf {
  strings:
    $key_cdbf = { 99 d7 [2] ed cf [2] aa cd [2] ed dc [2] a3 d0 [2] af da [2] b8 d1 [2] a3 9f [2] 9e }

  condition:
    any of them
}