rule TTP_XOR_WriteProcessMemory_067a {
  strings:
    $key_067a = { 51 08 [2] 63 2a [2] 65 1f [2] 4b 1f [2] 74 03 }

  condition:
    any of them
}