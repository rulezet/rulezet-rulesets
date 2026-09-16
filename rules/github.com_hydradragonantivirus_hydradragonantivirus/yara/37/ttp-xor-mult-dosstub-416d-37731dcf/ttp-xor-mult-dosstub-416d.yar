rule TTP_XOR_MULT_DOSStub_416d {
  strings:
    $key_416d = { 15 05 [2] 61 1d [2] 26 1f [2] 61 0e [2] 2f 02 [2] 23 08 [2] 34 03 [2] 2f 4d [2] 12 }

  condition:
    any of them
}