rule TTP_XOR_WriteProcessMemory_741a {
  strings:
    $key_741a = { 23 68 [2] 11 4a [2] 17 7f [2] 39 7f [2] 06 63 }

  condition:
    any of them
}