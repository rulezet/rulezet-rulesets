rule TTP_XOR_MULT_DOSStub_416b {
  strings:
    $key_416b = { 15 03 [2] 61 1b [2] 26 19 [2] 61 08 [2] 2f 04 [2] 23 0e [2] 34 05 [2] 2f 4b [2] 12 }

  condition:
    any of them
}