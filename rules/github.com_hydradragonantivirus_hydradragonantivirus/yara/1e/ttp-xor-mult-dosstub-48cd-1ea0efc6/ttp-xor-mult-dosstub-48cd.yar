rule TTP_XOR_MULT_DOSStub_48cd {
  strings:
    $key_48cd = { 1c a5 [2] 68 bd [2] 2f bf [2] 68 ae [2] 26 a2 [2] 2a a8 [2] 3d a3 [2] 26 ed [2] 1b }

  condition:
    any of them
}