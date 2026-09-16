rule TTP_XOR_MULT_DOSStub_ec2f {
  strings:
    $key_ec2f = { b8 47 [2] cc 5f [2] 8b 5d [2] cc 4c [2] 82 40 [2] 8e 4a [2] 99 41 [2] 82 0f [2] bf }

  condition:
    any of them
}