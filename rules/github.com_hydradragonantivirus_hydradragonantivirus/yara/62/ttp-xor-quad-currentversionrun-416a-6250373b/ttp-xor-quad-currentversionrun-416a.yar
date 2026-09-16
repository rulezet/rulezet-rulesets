rule TTP_XOR_QUAD_CurrentVersionRun_416a {
  strings:
    $key_416a = { 12 05 [2] 36 0b [2] 1d 27 [2] 33 05 [2] 27 1e [2] 28 04 [2] 36 19 [2] 34 18 [2] 2f 1e [2] 33 19 [2] 2f 36 }

  condition:
    any of them
}