rule TTP_XOR_WriteProcessMemory_c9ca {
  strings:
    $key_c9ca = { 9e b8 [2] ac 9a [2] aa af [2] 84 af [2] bb b3 }

  condition:
    any of them
}