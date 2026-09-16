rule TTP_XOR_MULT_DOSStub_ec2b {
  strings:
    $key_ec2b = { b8 43 [2] cc 5b [2] 8b 59 [2] cc 48 [2] 82 44 [2] 8e 4e [2] 99 45 [2] 82 0b [2] bf }

  condition:
    any of them
}