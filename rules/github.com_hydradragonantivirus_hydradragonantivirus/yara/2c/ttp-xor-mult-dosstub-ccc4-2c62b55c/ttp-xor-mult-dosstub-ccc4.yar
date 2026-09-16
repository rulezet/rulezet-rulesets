rule TTP_XOR_MULT_DOSStub_ccc4 {
  strings:
    $key_ccc4 = { 98 ac [2] ec b4 [2] ab b6 [2] ec a7 [2] a2 ab [2] ae a1 [2] b9 aa [2] a2 e4 [2] 9f }

  condition:
    any of them
}