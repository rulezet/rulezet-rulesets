rule TTP_XOR_MULT_DOSStub_ccc2 {
  strings:
    $key_ccc2 = { 98 aa [2] ec b2 [2] ab b0 [2] ec a1 [2] a2 ad [2] ae a7 [2] b9 ac [2] a2 e2 [2] 9f }

  condition:
    any of them
}