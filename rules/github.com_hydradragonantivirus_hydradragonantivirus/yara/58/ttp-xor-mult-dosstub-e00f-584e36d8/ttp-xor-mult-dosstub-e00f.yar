rule TTP_XOR_MULT_DOSStub_e00f {
  strings:
    $key_e00f = { b4 67 [2] c0 7f [2] 87 7d [2] c0 6c [2] 8e 60 [2] 82 6a [2] 95 61 [2] 8e 2f [2] b3 }

  condition:
    any of them
}