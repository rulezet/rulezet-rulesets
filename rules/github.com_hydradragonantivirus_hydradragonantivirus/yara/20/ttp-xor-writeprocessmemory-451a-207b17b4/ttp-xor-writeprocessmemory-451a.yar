rule TTP_XOR_WriteProcessMemory_451a {
  strings:
    $key_451a = { 12 68 [2] 20 4a [2] 26 7f [2] 08 7f [2] 37 63 }

  condition:
    any of them
}