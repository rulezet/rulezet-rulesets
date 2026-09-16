rule TTP_XOR_WriteProcessMemory_739a {
  strings:
    $key_739a = { 24 e8 [2] 16 ca [2] 10 ff [2] 3e ff [2] 01 e3 }

  condition:
    any of them
}