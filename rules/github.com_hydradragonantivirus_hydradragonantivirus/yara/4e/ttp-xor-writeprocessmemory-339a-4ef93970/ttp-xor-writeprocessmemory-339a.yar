rule TTP_XOR_WriteProcessMemory_339a {
  strings:
    $key_339a = { 64 e8 [2] 56 ca [2] 50 ff [2] 7e ff [2] 41 e3 }

  condition:
    any of them
}