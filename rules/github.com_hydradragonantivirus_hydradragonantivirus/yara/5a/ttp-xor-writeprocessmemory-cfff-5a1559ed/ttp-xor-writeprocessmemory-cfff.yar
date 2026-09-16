rule TTP_XOR_WriteProcessMemory_cfff {
  strings:
    $key_cfff = { 98 8d [2] aa af [2] ac 9a [2] 82 9a [2] bd 86 }

  condition:
    any of them
}