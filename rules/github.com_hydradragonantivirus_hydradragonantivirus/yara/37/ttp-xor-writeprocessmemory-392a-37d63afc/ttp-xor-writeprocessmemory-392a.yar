rule TTP_XOR_WriteProcessMemory_392a {
  strings:
    $key_392a = { 6e 58 [2] 5c 7a [2] 5a 4f [2] 74 4f [2] 4b 53 }

  condition:
    any of them
}