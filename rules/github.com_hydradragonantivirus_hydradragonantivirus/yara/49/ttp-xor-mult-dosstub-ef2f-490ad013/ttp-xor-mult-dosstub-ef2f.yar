rule TTP_XOR_MULT_DOSStub_ef2f {
  strings:
    $key_ef2f = { bb 47 [2] cf 5f [2] 88 5d [2] cf 4c [2] 81 40 [2] 8d 4a [2] 9a 41 [2] 81 0f [2] bc }

  condition:
    any of them
}