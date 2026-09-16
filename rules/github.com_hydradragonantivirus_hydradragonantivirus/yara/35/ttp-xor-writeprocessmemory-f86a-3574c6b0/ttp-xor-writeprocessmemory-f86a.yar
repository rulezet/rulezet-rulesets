rule TTP_XOR_WriteProcessMemory_f86a {
  strings:
    $key_f86a = { af 18 [2] 9d 3a [2] 9b 0f [2] b5 0f [2] 8a 13 }

  condition:
    any of them
}