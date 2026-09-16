rule TTP_XOR_WriteProcessMemory_131a {
  strings:
    $key_131a = { 44 68 [2] 76 4a [2] 70 7f [2] 5e 7f [2] 61 63 }

  condition:
    any of them
}