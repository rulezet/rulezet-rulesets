rule TTP_XOR_MULT_DOSStub_cd0f {
  strings:
    $key_cd0f = { 99 67 [2] ed 7f [2] aa 7d [2] ed 6c [2] a3 60 [2] af 6a [2] b8 61 [2] a3 2f [2] 9e }

  condition:
    any of them
}