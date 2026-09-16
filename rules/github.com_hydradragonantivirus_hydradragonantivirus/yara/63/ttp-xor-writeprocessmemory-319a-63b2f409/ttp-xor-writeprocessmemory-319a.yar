rule TTP_XOR_WriteProcessMemory_319a {
  strings:
    $key_319a = { 66 e8 [2] 54 ca [2] 52 ff [2] 7c ff [2] 43 e3 }

  condition:
    any of them
}