rule TTP_XOR_MULT_DOSStub_162a {
  strings:
    $key_162a = { 42 42 [2] 36 5a [2] 71 58 [2] 36 49 [2] 78 45 [2] 74 4f [2] 63 44 [2] 78 0a [2] 45 }

  condition:
    any of them
}