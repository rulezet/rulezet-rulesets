rule TTP_XOR_WriteProcessMemory_cc6a {
  strings:
    $key_cc6a = { 9b 18 [2] a9 3a [2] af 0f [2] 81 0f [2] be 13 }

  condition:
    any of them
}