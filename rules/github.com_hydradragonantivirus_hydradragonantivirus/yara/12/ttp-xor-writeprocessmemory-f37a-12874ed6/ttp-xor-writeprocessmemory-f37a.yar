rule TTP_XOR_WriteProcessMemory_f37a {
  strings:
    $key_f37a = { a4 08 [2] 96 2a [2] 90 1f [2] be 1f [2] 81 03 }

  condition:
    any of them
}