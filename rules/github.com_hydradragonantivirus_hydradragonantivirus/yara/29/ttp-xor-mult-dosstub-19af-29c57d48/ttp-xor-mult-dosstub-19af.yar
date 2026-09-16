rule TTP_XOR_MULT_DOSStub_19af {
  strings:
    $key_19af = { 4d c7 [2] 39 df [2] 7e dd [2] 39 cc [2] 77 c0 [2] 7b ca [2] 6c c1 [2] 77 8f [2] 4a }

  condition:
    any of them
}