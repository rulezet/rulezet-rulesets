rule TTP_XOR_WriteProcessMemory_039a {
  strings:
    $key_039a = { 54 e8 [2] 66 ca [2] 60 ff [2] 4e ff [2] 71 e3 }

  condition:
    any of them
}