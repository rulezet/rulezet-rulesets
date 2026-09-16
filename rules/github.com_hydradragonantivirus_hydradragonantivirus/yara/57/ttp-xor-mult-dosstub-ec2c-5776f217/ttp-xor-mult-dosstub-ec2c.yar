rule TTP_XOR_MULT_DOSStub_ec2c {
  strings:
    $key_ec2c = { b8 44 [2] cc 5c [2] 8b 5e [2] cc 4f [2] 82 43 [2] 8e 49 [2] 99 42 [2] 82 0c [2] bf }

  condition:
    any of them
}