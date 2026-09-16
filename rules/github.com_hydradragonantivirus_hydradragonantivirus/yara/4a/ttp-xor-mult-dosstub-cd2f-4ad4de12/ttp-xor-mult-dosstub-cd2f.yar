rule TTP_XOR_MULT_DOSStub_cd2f {
  strings:
    $key_cd2f = { 99 47 [2] ed 5f [2] aa 5d [2] ed 4c [2] a3 40 [2] af 4a [2] b8 41 [2] a3 0f [2] 9e }

  condition:
    any of them
}