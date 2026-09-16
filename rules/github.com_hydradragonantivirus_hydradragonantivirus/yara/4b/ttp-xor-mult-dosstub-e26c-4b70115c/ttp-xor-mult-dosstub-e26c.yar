rule TTP_XOR_MULT_DOSStub_e26c {
  strings:
    $key_e26c = { b6 04 [2] c2 1c [2] 85 1e [2] c2 0f [2] 8c 03 [2] 80 09 [2] 97 02 [2] 8c 4c [2] b1 }

  condition:
    any of them
}