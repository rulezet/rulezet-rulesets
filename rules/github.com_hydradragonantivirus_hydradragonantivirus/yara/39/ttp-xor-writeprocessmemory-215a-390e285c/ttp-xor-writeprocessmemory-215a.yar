rule TTP_XOR_WriteProcessMemory_215a {
  strings:
    $key_215a = { 76 28 [2] 44 0a [2] 42 3f [2] 6c 3f [2] 53 23 }

  condition:
    any of them
}