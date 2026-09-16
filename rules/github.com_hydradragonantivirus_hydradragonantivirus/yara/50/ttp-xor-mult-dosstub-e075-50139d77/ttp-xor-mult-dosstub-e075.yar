rule TTP_XOR_MULT_DOSStub_e075 {
  strings:
    $key_e075 = { b4 1d [2] c0 05 [2] 87 07 [2] c0 16 [2] 8e 1a [2] 82 10 [2] 95 1b [2] 8e 55 [2] b3 }

  condition:
    any of them
}