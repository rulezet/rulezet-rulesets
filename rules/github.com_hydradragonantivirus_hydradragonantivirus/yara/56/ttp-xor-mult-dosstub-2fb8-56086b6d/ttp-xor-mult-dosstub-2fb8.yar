rule TTP_XOR_MULT_DOSStub_2fb8 {
  strings:
    $key_2fb8 = { 7b d0 [2] 0f c8 [2] 48 ca [2] 0f db [2] 41 d7 [2] 4d dd [2] 5a d6 [2] 41 98 [2] 7c }

  condition:
    any of them
}