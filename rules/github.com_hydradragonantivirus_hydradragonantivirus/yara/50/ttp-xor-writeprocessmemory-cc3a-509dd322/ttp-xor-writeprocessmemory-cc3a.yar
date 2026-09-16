rule TTP_XOR_WriteProcessMemory_cc3a {
  strings:
    $key_cc3a = { 9b 48 [2] a9 6a [2] af 5f [2] 81 5f [2] be 43 }

  condition:
    any of them
}