rule TTP_XOR_WriteProcessMemory_092a {
  strings:
    $key_092a = { 5e 58 [2] 6c 7a [2] 6a 4f [2] 44 4f [2] 7b 53 }

  condition:
    any of them
}