rule TTP_XOR_WriteProcessMemory_615a {
  strings:
    $key_615a = { 36 28 [2] 04 0a [2] 02 3f [2] 2c 3f [2] 13 23 }

  condition:
    any of them
}