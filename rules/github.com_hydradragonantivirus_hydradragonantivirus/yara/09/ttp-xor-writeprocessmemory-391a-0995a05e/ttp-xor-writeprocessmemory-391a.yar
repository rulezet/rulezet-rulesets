rule TTP_XOR_WriteProcessMemory_391a {
  strings:
    $key_391a = { 6e 68 [2] 5c 4a [2] 5a 7f [2] 74 7f [2] 4b 63 }

  condition:
    any of them
}