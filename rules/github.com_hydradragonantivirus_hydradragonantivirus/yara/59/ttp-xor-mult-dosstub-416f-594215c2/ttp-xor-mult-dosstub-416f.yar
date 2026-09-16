rule TTP_XOR_MULT_DOSStub_416f {
  strings:
    $key_416f = { 15 07 [2] 61 1f [2] 26 1d [2] 61 0c [2] 2f 00 [2] 23 0a [2] 34 01 [2] 2f 4f [2] 12 }

  condition:
    any of them
}