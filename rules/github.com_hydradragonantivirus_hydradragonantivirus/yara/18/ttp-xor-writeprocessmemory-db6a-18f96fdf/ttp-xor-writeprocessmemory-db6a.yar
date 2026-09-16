rule TTP_XOR_WriteProcessMemory_db6a {
  strings:
    $key_db6a = { 8c 18 [2] be 3a [2] b8 0f [2] 96 0f [2] a9 13 }

  condition:
    any of them
}