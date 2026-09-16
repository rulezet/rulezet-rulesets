rule TTP_XOR_MULT_DOSStub_7951 {
  strings:
    $key_7951 = { 2d 39 [2] 59 21 [2] 1e 23 [2] 59 32 [2] 17 3e [2] 1b 34 [2] 0c 3f [2] 17 71 [2] 2a }

  condition:
    any of them
}