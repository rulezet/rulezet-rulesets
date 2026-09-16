rule TTP_XOR_MULT_DOSStub_ec2d {
  strings:
    $key_ec2d = { b8 45 [2] cc 5d [2] 8b 5f [2] cc 4e [2] 82 42 [2] 8e 48 [2] 99 43 [2] 82 0d [2] bf }

  condition:
    any of them
}