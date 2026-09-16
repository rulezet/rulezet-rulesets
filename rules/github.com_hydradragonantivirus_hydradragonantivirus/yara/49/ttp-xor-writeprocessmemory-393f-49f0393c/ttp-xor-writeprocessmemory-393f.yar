rule TTP_XOR_WriteProcessMemory_393f {
  strings:
    $key_393f = { 6e 4d [2] 5c 6f [2] 5a 5a [2] 74 5a [2] 4b 46 }

  condition:
    any of them
}