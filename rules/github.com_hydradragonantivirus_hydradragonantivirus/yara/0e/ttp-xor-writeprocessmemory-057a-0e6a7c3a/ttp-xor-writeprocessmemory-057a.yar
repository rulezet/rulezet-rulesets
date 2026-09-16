rule TTP_XOR_WriteProcessMemory_057a {
  strings:
    $key_057a = { 52 08 [2] 60 2a [2] 66 1f [2] 48 1f [2] 77 03 }

  condition:
    any of them
}