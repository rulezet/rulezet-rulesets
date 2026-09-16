rule TTP_XOR_WriteProcessMemory_a19a {
  strings:
    $key_a19a = { f6 e8 [2] c4 ca [2] c2 ff [2] ec ff [2] d3 e3 }

  condition:
    any of them
}