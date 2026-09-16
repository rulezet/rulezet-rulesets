rule TTP_XOR_MULT_DOSStub_e335 {
  strings:
    $key_e335 = { b7 5d [2] c3 45 [2] 84 47 [2] c3 56 [2] 8d 5a [2] 81 50 [2] 96 5b [2] 8d 15 [2] b0 }

  condition:
    any of them
}