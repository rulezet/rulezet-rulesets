rule TTP_XOR_WriteProcessMemory_214a {
  strings:
    $key_214a = { 76 38 [2] 44 1a [2] 42 2f [2] 6c 2f [2] 53 33 }

  condition:
    any of them
}