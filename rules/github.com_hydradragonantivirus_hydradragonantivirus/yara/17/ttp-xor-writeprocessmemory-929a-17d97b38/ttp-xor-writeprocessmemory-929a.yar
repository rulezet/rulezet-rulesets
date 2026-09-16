rule TTP_XOR_WriteProcessMemory_929a {
  strings:
    $key_929a = { c5 e8 [2] f7 ca [2] f1 ff [2] df ff [2] e0 e3 }

  condition:
    any of them
}