rule TTP_XOR_MULT_DOSStub_54ed {
  strings:
    $key_54ed = { 00 85 [2] 74 9d [2] 33 9f [2] 74 8e [2] 3a 82 [2] 36 88 [2] 21 83 [2] 3a cd [2] 07 }

  condition:
    any of them
}