rule TTP_XOR_MULT_DOSStub_e01f {
  strings:
    $key_e01f = { b4 77 [2] c0 6f [2] 87 6d [2] c0 7c [2] 8e 70 [2] 82 7a [2] 95 71 [2] 8e 3f [2] b3 }

  condition:
    any of them
}