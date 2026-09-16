rule TTP_XOR_MULT_DOSStub_b64d {
  strings:
    $key_b64d = { e2 25 [2] 96 3d [2] d1 3f [2] 96 2e [2] d8 22 [2] d4 28 [2] c3 23 [2] d8 6d [2] e5 }

  condition:
    any of them
}