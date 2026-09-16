rule TTP_XOR_MULT_DOSStub_cca5 {
  strings:
    $key_cca5 = { 98 cd [2] ec d5 [2] ab d7 [2] ec c6 [2] a2 ca [2] ae c0 [2] b9 cb [2] a2 85 [2] 9f }

  condition:
    any of them
}