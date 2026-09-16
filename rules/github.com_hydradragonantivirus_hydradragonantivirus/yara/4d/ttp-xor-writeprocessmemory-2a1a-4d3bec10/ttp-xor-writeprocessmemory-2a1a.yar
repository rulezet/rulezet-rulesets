rule TTP_XOR_WriteProcessMemory_2a1a {
  strings:
    $key_2a1a = { 7d 68 [2] 4f 4a [2] 49 7f [2] 67 7f [2] 58 63 }

  condition:
    any of them
}