rule TTP_XOR_MULT_DOSStub_88af {
  strings:
    $key_88af = { dc c7 [2] a8 df [2] ef dd [2] a8 cc [2] e6 c0 [2] ea ca [2] fd c1 [2] e6 8f [2] db }

  condition:
    any of them
}