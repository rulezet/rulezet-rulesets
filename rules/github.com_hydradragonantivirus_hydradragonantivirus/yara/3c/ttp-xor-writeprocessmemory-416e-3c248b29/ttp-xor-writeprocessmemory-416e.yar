rule TTP_XOR_WriteProcessMemory_416e {
  strings:
    $key_416e = { 16 1c [2] 24 3e [2] 22 0b [2] 0c 0b [2] 33 17 }

  condition:
    any of them
}