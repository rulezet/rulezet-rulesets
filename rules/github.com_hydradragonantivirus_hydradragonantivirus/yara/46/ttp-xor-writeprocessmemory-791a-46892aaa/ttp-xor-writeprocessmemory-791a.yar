rule TTP_XOR_WriteProcessMemory_791a {
  strings:
    $key_791a = { 2e 68 [2] 1c 4a [2] 1a 7f [2] 34 7f [2] 0b 63 }

  condition:
    any of them
}