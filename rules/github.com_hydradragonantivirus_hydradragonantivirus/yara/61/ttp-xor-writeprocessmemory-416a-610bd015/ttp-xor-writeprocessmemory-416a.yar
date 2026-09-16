rule TTP_XOR_WriteProcessMemory_416a {
  strings:
    $key_416a = { 16 18 [2] 24 3a [2] 22 0f [2] 0c 0f [2] 33 13 }

  condition:
    any of them
}