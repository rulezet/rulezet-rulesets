rule TTP_XOR_MULT_DOSStub_0f32 {
  strings:
    $key_0f32 = { 5b 5a [2] 2f 42 [2] 68 40 [2] 2f 51 [2] 61 5d [2] 6d 57 [2] 7a 5c [2] 61 12 [2] 5c }

  condition:
    any of them
}