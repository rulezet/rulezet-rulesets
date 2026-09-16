rule TTP_XOR_MULT_DOSStub_ec2e {
  strings:
    $key_ec2e = { b8 46 [2] cc 5e [2] 8b 5c [2] cc 4d [2] 82 41 [2] 8e 4b [2] 99 40 [2] 82 0e [2] bf }

  condition:
    any of them
}