rule TTP_XOR_MULT_DOSStub_3fb8 {
  strings:
    $key_3fb8 = { 6b d0 [2] 1f c8 [2] 58 ca [2] 1f db [2] 51 d7 [2] 5d dd [2] 4a d6 [2] 51 98 [2] 6c }

  condition:
    any of them
}