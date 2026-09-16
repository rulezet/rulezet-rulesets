rule TTP_XOR_WriteProcessMemory_659a {
  strings:
    $key_659a = { 32 e8 [2] 00 ca [2] 06 ff [2] 28 ff [2] 17 e3 }

  condition:
    any of them
}