rule TTP_XOR_WriteProcessMemory_066a {
  strings:
    $key_066a = { 51 18 [2] 63 3a [2] 65 0f [2] 4b 0f [2] 74 13 }

  condition:
    any of them
}