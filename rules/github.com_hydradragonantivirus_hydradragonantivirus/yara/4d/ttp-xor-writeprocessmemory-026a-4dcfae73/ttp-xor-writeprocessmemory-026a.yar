rule TTP_XOR_WriteProcessMemory_026a {
  strings:
    $key_026a = { 55 18 [2] 67 3a [2] 61 0f [2] 4f 0f [2] 70 13 }

  condition:
    any of them
}