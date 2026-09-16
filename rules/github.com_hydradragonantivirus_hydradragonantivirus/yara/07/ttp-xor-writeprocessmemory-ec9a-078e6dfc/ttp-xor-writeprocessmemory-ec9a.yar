rule TTP_XOR_WriteProcessMemory_ec9a {
  strings:
    $key_ec9a = { bb e8 [2] 89 ca [2] 8f ff [2] a1 ff [2] 9e e3 }

  condition:
    any of them
}