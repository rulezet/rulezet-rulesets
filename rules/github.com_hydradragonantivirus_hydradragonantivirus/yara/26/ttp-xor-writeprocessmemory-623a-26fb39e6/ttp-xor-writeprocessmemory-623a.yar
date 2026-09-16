rule TTP_XOR_WriteProcessMemory_623a {
  strings:
    $key_623a = { 35 48 [2] 07 6a [2] 01 5f [2] 2f 5f [2] 10 43 }

  condition:
    any of them
}