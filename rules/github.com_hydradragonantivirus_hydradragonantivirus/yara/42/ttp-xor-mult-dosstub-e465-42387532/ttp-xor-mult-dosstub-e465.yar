rule TTP_XOR_MULT_DOSStub_e465 {
  strings:
    $key_e465 = { b0 0d [2] c4 15 [2] 83 17 [2] c4 06 [2] 8a 0a [2] 86 00 [2] 91 0b [2] 8a 45 [2] b7 }

  condition:
    any of them
}